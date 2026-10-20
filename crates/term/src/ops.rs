//! Iterative comparison and object sizing.
use crate::FunRef;
use crate::identity::node_order;
use crate::{
    ARITY, BIN_REF, EMPTY_TUPLE, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, FLOAT, FUN, HEAP_BITS,
    Identity, MAP, NEG_BIG, POS_BIG, RECORD, REF, SUB_BITS, Term, TermKind, global_atoms,
};
use smallvec::SmallVec;
use std::cmp::Ordering;

/// Add two small integers, preserving their tag and detecting 60-bit overflow.
#[inline]
pub fn small_add(a: Term, b: Term) -> Option<Term> {
    let (a, b) = (a.bits(), b.bits());
    if a & 15 != 15 || b & 15 != 15 {
        return None;
    }
    let sum = a.wrapping_add(b).wrapping_sub(15);
    if ((a ^ sum) & (b ^ sum) & (1 << 63)) != 0 {
        None
    } else {
        Some(Term(sum))
    }
}
/// Subtract two small integers with overflow detection.
#[inline]
pub fn small_sub(a: Term, b: Term) -> Option<Term> {
    let (a, b) = (a.bits(), b.bits());
    if a & 15 != 15 || b & 15 != 15 {
        return None;
    }
    let difference = a.wrapping_sub(b).wrapping_add(15);
    if ((a ^ b) & (a ^ difference) & (1 << 63)) != 0 {
        None
    } else {
        Some(Term(difference))
    }
}
/// Multiply two small integers with overflow detection.
#[inline]
pub fn small_mul(a: Term, b: Term) -> Option<Term> {
    a.as_small()?
        .checked_mul(b.as_small()?)
        .and_then(Term::small)
}

fn number(term: Term) -> Option<Number> {
    if let Some(n) = term.as_small() {
        return Some(Number::Integer(Integer::Small(n)));
    }
    let h = term.header()?;
    // SAFETY: A live boxed number is laid out according to its header.
    let p = unsafe { term.raw_ptr() };
    match h & 63 {
        FLOAT => {
            // SAFETY: A float reserves header plus one payload word.
            Some(Number::Float(f64::from_bits(unsafe { *p.add(1) })))
        }
        POS_BIG | NEG_BIG => {
            let mut digits = SmallVec::new();
            term.with_bignum_digits_mut(|words| digits.extend_from_slice(words))?;
            Some(Number::Integer(Integer::Big {
                negative: h & 63 == NEG_BIG,
                digits,
            }))
        }
        _ => None,
    }
}
enum Number {
    Integer(Integer),
    Float(f64),
}
enum Integer {
    Small(i64),
    Big {
        negative: bool,
        digits: SmallVec<[u64; 4]>,
    },
}
impl Integer {
    fn negative(&self) -> bool {
        match self {
            Self::Small(n) => *n < 0,
            Self::Big { negative, .. } => *negative,
        }
    }

    fn zero(&self) -> bool {
        match self {
            Self::Small(n) => *n == 0,
            Self::Big { digits, .. } => digits.is_empty() || digits.iter().all(|d| *d == 0),
        }
    }

    fn magnitude_len(&self) -> usize {
        match self {
            Self::Small(n) => usize::from(*n != 0),
            Self::Big { digits, .. } => digits.len(),
        }
    }

    fn magnitude_digit(&self, index: usize) -> u64 {
        match self {
            Self::Small(n) => {
                if index == 0 {
                    n.unsigned_abs()
                } else {
                    0
                }
            }
            Self::Big { digits, .. } => digits.get(index).copied().unwrap_or(0),
        }
    }
}

fn cmp_magnitude(a: &Integer, b: &Integer) -> Ordering {
    let alen = a.magnitude_len();
    let blen = b.magnitude_len();
    alen.cmp(&blen).then_with(|| {
        (0..alen)
            .rev()
            .map(|index| a.magnitude_digit(index).cmp(&b.magnitude_digit(index)))
            .find(|order| *order != Ordering::Equal)
            .unwrap_or(Ordering::Equal)
    })
}

/// Compare integer magnitudes without considering signs.
///
/// Port of erts/emulator/beam/erl_arith.c:1208 (`big_ucomp`), OTP-29.1.1.
pub fn integer_magnitude_cmp(a: Term, b: Term) -> Option<Ordering> {
    match (number(a)?, number(b)?) {
        (Number::Integer(a), Number::Integer(b)) => Some(cmp_magnitude(&a, &b)),
        _ => None,
    }
}

fn integer_cmp(a: &Integer, b: &Integer) -> Ordering {
    if a.zero() && b.zero() {
        return Ordering::Equal;
    }
    match (a.negative(), b.negative()) {
        (true, false) => Ordering::Less,
        (false, true) => Ordering::Greater,
        (negative, _) => {
            let order = cmp_magnitude(a, b);
            if negative { order.reverse() } else { order }
        }
    }
}

fn integer_float_cmp(n: &Integer, f: f64) -> Ordering {
    if f.is_nan() {
        return Ordering::Less;
    }
    if f.is_infinite() {
        return if f.is_sign_positive() {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    if f == 0.0 {
        return if n.zero() {
            Ordering::Equal
        } else if n.negative() {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }
    let n_negative = n.negative();
    let f_negative = f.is_sign_negative();
    if n_negative != f_negative {
        return if n_negative {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }

    // Compare unsigned limb magnitudes with the exact IEEE-754 significand.
    let bits = f.to_bits();
    let exponent = ((bits >> 52) & 0x7ff) as i32;
    let mantissa = bits & ((1_u64 << 52) - 1);
    let (significand, shift) = if exponent == 0 {
        (mantissa, -1074)
    } else {
        (mantissa | (1_u64 << 52), exponent - 1023 - 52)
    };
    let magnitude_order = if shift >= 0 {
        let shift = shift as usize;
        let base = shift / 64;
        let offset = shift % 64;
        let shifted = (significand as u128) << offset;
        let low = shifted as u64;
        let high = (shifted >> 64) as u64;
        let high_index = if high != 0 { base + 1 } else { base };
        n.magnitude_len().cmp(&(high_index + 1)).then_with(|| {
            (0..=high_index)
                .rev()
                .map(|index| {
                    let float_digit = if index == base {
                        low
                    } else if index == base + 1 {
                        high
                    } else {
                        0
                    };
                    n.magnitude_digit(index).cmp(&float_digit)
                })
                .find(|order| *order != Ordering::Equal)
                .unwrap_or(Ordering::Equal)
        })
    } else {
        let fractional_bits = (-shift) as usize;
        let float_exponent =
            (63 - significand.leading_zeros() as usize) as i32 - fractional_bits as i32;
        if n.zero() {
            Ordering::Less
        } else if float_exponent < 0 {
            Ordering::Greater
        } else {
            let integer_bits = (n.magnitude_len() - 1) * 64
                + (64 - n.magnitude_digit(n.magnitude_len() - 1).leading_zeros() as usize);
            let float_bits = float_exponent as usize + 1;
            integer_bits.cmp(&float_bits).then_with(|| {
                let floor = significand >> fractional_bits;
                let floor_order = cmp_magnitude(n, &Integer::Small(floor as i64));
                if floor_order != Ordering::Equal {
                    floor_order
                } else {
                    let fractional_mask = (1_u64 << fractional_bits) - 1;
                    if significand & fractional_mask == 0 {
                        Ordering::Equal
                    } else {
                        Ordering::Less
                    }
                }
            })
        }
    };
    if n_negative {
        magnitude_order.reverse()
    } else {
        magnitude_order
    }
}
fn number_cmp(a: Term, b: Term, exact: bool) -> Ordering {
    match (number(a).unwrap(), number(b).unwrap()) {
        (Number::Integer(a), Number::Integer(b)) => integer_cmp(&a, &b),
        (Number::Float(a), Number::Float(b)) => {
            let c = a.total_cmp(&b);
            if !exact && a == b { Ordering::Equal } else { c }
        }
        (Number::Integer(_), Number::Float(_)) if exact => Ordering::Less,
        (Number::Float(_), Number::Integer(_)) if exact => Ordering::Greater,
        (Number::Integer(a), Number::Float(b)) => {
            if exact {
                return Ordering::Less;
            }
            integer_float_cmp(&a, b)
        }
        (Number::Float(a), Number::Integer(b)) => {
            if exact {
                return Ordering::Greater;
            }
            integer_float_cmp(&b, a).reverse()
        }
    }
}
fn bits_cmp(a: Term, b: Term) -> Ordering {
    // Port of erts/emulator/beam/erl_bits.h:560 and erl_bits.c:2293-2372,
    // OTP-29.1.1. The offsets belong to the compared bitstrings, including
    // SUB_BITS views over a byte-aligned literal or reference binary.
    // SAFETY: comparison requires both owning heaps to remain live.
    let a = unsafe { a.binary_ref().unwrap() };
    // SAFETY: comparison requires both owning heaps to remain live.
    let b = unsafe { b.binary_ref().unwrap() };
    let common_bits = a.bit_len().min(b.bit_len());
    let (a_start, b_start) = (a.start_bit(), b.start_bit());
    if (a_start | b_start | common_bits).is_multiple_of(8) {
        let a_bytes = &a.bytes()[a_start / 8..][..common_bits / 8];
        let b_bytes = &b.bytes()[b_start / 8..][..common_bits / 8];
        let order = a_bytes.cmp(b_bytes);
        if order != Ordering::Equal {
            return order;
        }
    } else {
        for i in 0..common_bits {
            let a_bit = (a.bytes()[(a_start + i) / 8] >> (7 - (a_start + i) % 8)) & 1;
            let b_bit = (b.bytes()[(b_start + i) / 8] >> (7 - (b_start + i) % 8)) & 1;
            match a_bit.cmp(&b_bit) {
                Ordering::Equal => {}
                c => return c,
            }
        }
    }
    a.bit_len().cmp(&b.bit_len())
}
pub(crate) struct Children {
    ptr: *const u64,
    next: usize,
    end: usize,
}
impl Iterator for Children {
    type Item = Term;
    #[inline]
    fn next(&mut self) -> Option<Term> {
        if self.next == self.end {
            return None;
        }
        // SAFETY: children() derives this range from a live, initialized term.
        let child = unsafe { Term(*self.ptr.add(self.next)) };
        self.next += 1;
        Some(child)
    }
}
pub(crate) fn children(term: Term) -> Children {
    if term.bits() & 3 == 1 {
        return Children {
            // SAFETY: the caller keeps the cons cell live.
            ptr: unsafe { term.raw_ptr() },
            next: 0,
            end: 2,
        };
    }
    if let Some(header) = term.header() {
        // SAFETY: the caller keeps the boxed object live and initialized.
        let ptr = unsafe { term.raw_ptr() };
        // SAFETY: the header determines initialized term-bearing slots.
        let range = unsafe { crate::hamt::boxed_term_range(header, ptr) };
        return Children {
            ptr,
            next: range.start,
            end: range.end,
        };
    }
    Children {
        ptr: std::ptr::null(),
        next: 0,
        end: 0,
    }
}
/// Number of words needed for a deep copy, counting shared objects each time.
/// Port of `erts/emulator/beam/copy.c:88` (`size_object_x`), OTP-29.1.1.
pub fn size_object(root: Term) -> usize {
    size_object_x(root, None)
}

/// Words a literal-aware copy needs: literals outside the purge area are not copied.
/// Port of erts/emulator/beam/copy.c:88 (size_object_x with a litopt), OTP-29.1.1.
pub fn size_object_litopt(root: Term, literals: &crate::LiteralAreas) -> usize {
    size_object_x(root, Some(literals))
}

/// Flat size of `obj`. Sharing is not collapsed. Literals outside the purge area
/// contribute nothing when `litopt` is set.
/// Port of erts/emulator/beam/copy.c:88 (`size_object_x`), OTP-29.1.1.
pub(crate) fn size_object_x(mut obj: Term, litopt: Option<&crate::LiteralAreas>) -> usize {
    // `DECLARE_ESTACK` starts at DEF_ESTACK_SIZE (global.h:322).
    let mut stack: SmallVec<[Term; 16]> = SmallVec::new();
    let mut sum = 0usize;
    // SAFETY: `obj` and every child pushed below are live terms owned by the caller.
    // Each raw read is the word `size_object_x` reads for that primary tag or header.
    unsafe {
        loop {
            match obj.0 & 3 {
                1 => {
                    let ptr = obj.raw_ptr();
                    if lit_kept(litopt, ptr) {
                        pop_size(&mut stack, &mut obj);
                        if obj.0 == u64::MAX {
                            return sum;
                        }
                        continue;
                    }
                    sum += 2;
                    let head = Term(*ptr);
                    if !head.is_immed() {
                        stack.push(head);
                    }
                    obj = Term(*ptr.add(1));
                }
                2 => {
                    let ptr = obj.raw_ptr();
                    if lit_kept(litopt, ptr) {
                        pop_size(&mut stack, &mut obj);
                        if obj.0 == u64::MAX {
                            return sum;
                        }
                        continue;
                    }
                    let hdr = *ptr;
                    match hdr & 63 {
                        crate::ARITY | crate::RECORD => {
                            let arity = (hdr >> 6) as usize;
                            // Empty tuple is the global literal and adds no words (copy.c:130).
                            if arity == 0 {
                                pop_size(&mut stack, &mut obj);
                                if obj.0 == u64::MAX {
                                    return sum;
                                }
                                continue;
                            }
                            sum += arity + 1;
                            for i in 1..arity {
                                let child = Term(*ptr.add(i));
                                if !child.is_immed() {
                                    stack.push(child);
                                }
                            }
                            obj = Term(*ptr.add(arity));
                        }
                        crate::FUN => {
                            // ERL_FUN_SIZE is 2 (thing word + entry); env is the flexible tail.
                            let nfree = ((hdr >> 16) & 255) as usize;
                            sum += 2 + nfree;
                            if nfree == 0 {
                                pop_size(&mut stack, &mut obj);
                                if obj.0 == u64::MAX {
                                    return sum;
                                }
                                continue;
                            }
                            for i in 1..nfree {
                                let env = Term(*ptr.add(2 + i));
                                if !env.is_immed() {
                                    stack.push(env);
                                }
                            }
                            obj = Term(*ptr.add(2));
                        }
                        crate::MAP => match (hdr >> 6) & 3 {
                            0 => {
                                let n = (*ptr.add(1) as usize) + 1;
                                sum += n + 2;
                                let mut child = ptr.add(2);
                                for _ in 0..n {
                                    let term = Term(*child);
                                    child = child.add(1);
                                    if !term.is_immed() {
                                        stack.push(term);
                                    }
                                }
                                pop_size(&mut stack, &mut obj);
                                if obj.0 == u64::MAX {
                                    return sum;
                                }
                            }
                            1..=3 => {
                                let sz = ((hdr >> 16) as u16).count_ones() as usize;
                                let hdr_arity = if (hdr >> 6) & 3 == 1 {
                                    0
                                } else {
                                    ((hdr >> 8) & 0xff) as usize
                                };
                                sum += 1 + sz + hdr_arity;
                                if sz == 0 {
                                    pop_size(&mut stack, &mut obj);
                                    if obj.0 == u64::MAX {
                                        return sum;
                                    }
                                    continue;
                                }
                                let head = ptr.add(1 + hdr_arity);
                                let mut left = sz;
                                while left > 1 {
                                    left -= 1;
                                    let term = Term(*head.add(left));
                                    if !term.is_immed() {
                                        stack.push(term);
                                    }
                                }
                                obj = Term(*head);
                            }
                            _ => unreachable!(),
                        },
                        crate::SUB_BITS => {
                            let orig = Term(*ptr.add(4));
                            let underlying = *orig.raw_ptr();
                            if underlying == (2 << 6) | crate::BIN_REF {
                                // Sub-bits and its BinRef are one unit (copy.c:224-230).
                                sum += 8;
                            } else {
                                // Match context over a heap bitstring: the copy is a
                                // heap bitstring of the window, not the context (copy.c:233-238).
                                let bits =
                                    (*ptr.add(3) as usize).wrapping_sub(*ptr.add(2) as usize);
                                sum += heap_bits_words(bits);
                            }
                            pop_size(&mut stack, &mut obj);
                            if obj.0 == u64::MAX {
                                return sum;
                            }
                        }
                        _ => {
                            sum += ((hdr >> 6) as usize) + 1;
                            pop_size(&mut stack, &mut obj);
                            if obj.0 == u64::MAX {
                                return sum;
                            }
                        }
                    }
                }
                3 => {
                    pop_size(&mut stack, &mut obj);
                    if obj.0 == u64::MAX {
                        return sum;
                    }
                }
                _ => {
                    debug_assert!(false, "size_object: bad tag {:#x}", obj.0);
                    pop_size(&mut stack, &mut obj);
                    if obj.0 == u64::MAX {
                        return sum;
                    }
                }
            }
        }
    }
}

#[inline]
fn lit_kept(litopt: Option<&crate::LiteralAreas>, ptr: *const u64) -> bool {
    // Port of copy.c:105 (`litopt && erts_is_literal && !in_literal_purge_area`).
    litopt.is_some_and(|areas| areas.keeps(ptr as u64))
}

#[inline]
fn pop_size(stack: &mut SmallVec<[Term; 16]>, obj: &mut Term) {
    match stack.pop() {
        Some(next) => *obj = next,
        None => *obj = Term(u64::MAX),
    }
}

#[inline]
fn heap_bits_words(num_bits: usize) -> usize {
    // Port of erl_bits.h:156-161 (`heap_bits_size`).
    let nbytes = num_bits.div_ceil(8);
    2 + nbytes.div_ceil(8)
}

/// `erts_debug:size_shared/1`: words with sharing preserved, ignoring every literal.
/// Port of erts/emulator/beam/copy.c:319 (size_shared), OTP-29.1.1.
pub fn size_shared(root: Term) -> usize {
    let literals = crate::LiteralAreas::current();
    size_object_inner(
        root,
        true,
        std::collections::HashSet::new(),
        LiteralSkip::All(&literals),
        None,
    )
}

/// Which literal objects a sizing or copying traversal leaves in place.
#[derive(Clone, Copy)]
pub(crate) enum LiteralSkip<'a> {
    /// Copy literals like ordinary heap objects (`size_object`, `copy_struct`).
    None,
    /// Keep literals outside the collector's purge area (`litopt`).
    Kept(&'a crate::LiteralAreas),
    /// Keep every literal (`size_shared`).
    All(&'a crate::LiteralAreas),
}

impl LiteralSkip<'_> {
    // erts expands erts_is_literal inline (global.h:1572 macro), OTP-29.1.1.
    #[inline]
    pub(crate) fn skips(self, address: u64) -> bool {
        match self {
            Self::None => false,
            Self::Kept(literals) => literals.keeps(address),
            Self::All(literals) => literals.is_literal(address),
        }
    }
}

/// Number of words needed by a deep copy that preserves object aliases.
/// Port of erts/emulator/beam/copy.c:1111 (copy_shared_calculate), OTP-29.1.1.
pub fn size_object_preserving_sharing(root: Term) -> usize {
    size_object_preserving_sharing_after(root, [])
}

/// Count words not already visited by a shared-copy operation.
pub fn size_object_preserving_sharing_after(
    root: Term,
    seen: impl IntoIterator<Item = u64>,
) -> usize {
    size_object_inner(
        root,
        true,
        seen.into_iter().collect(),
        LiteralSkip::None,
        None,
    )
}

pub(crate) fn size_object_inner(
    root: Term,
    preserve_sharing: bool,
    mut visited: std::collections::HashSet<u64>,
    skip: LiteralSkip<'_>,
    unshared_literals: Option<&crate::LiteralAreas>,
) -> usize {
    // Sharing preservation is `copy_shared_calculate`. The default copier is
    // `size_object_x` and does not build a visited set (copy.c:88).
    if !preserve_sharing {
        return match skip {
            LiteralSkip::None => size_object_x(root, None),
            LiteralSkip::Kept(areas) => size_object_x(root, Some(areas)),
            LiteralSkip::All(_) => {
                size_object_with_prior(root, false, &mut visited, None, skip, unshared_literals)
            }
        };
    }
    size_object_with_prior(
        root,
        preserve_sharing,
        &mut visited,
        None,
        skip,
        unshared_literals,
    )
}

/// Like `size_object_inner`, but objects already copied by earlier roots of the
/// same shared-copy operation (`prior`) are looked up in place instead of being
/// re-collected into a fresh set per root (quadratic over a large message queue).
pub(crate) fn size_object_with_prior(
    root: Term,
    preserve_sharing: bool,
    visited: &mut std::collections::HashSet<u64>,
    prior: Option<&std::collections::HashMap<u64, Term>>,
    skip: LiteralSkip<'_>,
    unshared_literals: Option<&crate::LiteralAreas>,
) -> usize {
    let seen_before = |address: u64| prior.is_some_and(|p| p.contains_key(&address));
    let mut size = 0;
    // Most copied terms (table rows, small messages) fit inline: no allocation per call.
    let mut stack: SmallVec<[Term; 32]> = SmallVec::new();
    let mut current = Some(root);
    while let Some(mut term) = current.take().or_else(|| stack.pop()) {
        while term.bits() & 3 == 1 {
            // SAFETY: every traversed cons cell is live and initialized. An
            // adjacent predecessor is read only after its tagged tail proves
            // that it is the next cell in this list.
            unsafe {
                let mut ptr = term.raw_ptr();
                loop {
                    if skip.skips(ptr as usize as u64) {
                        term = Term::NIL;
                        break;
                    }
                    // Port of erts/emulator/beam/copy.c:1164-1170 (copy_shared_calculate
                    // adds size_object of a copied literal), OTP-29.1.1.
                    if preserve_sharing
                        && unshared_literals.is_some_and(|l| l.is_literal(ptr as usize as u64))
                    {
                        size += size_object(Term(ptr as u64 | 1));
                        term = Term::NIL;
                        break;
                    }
                    if preserve_sharing
                        && (seen_before(ptr as usize as u64)
                            || !visited.insert(ptr as usize as u64))
                    {
                        term = Term::NIL;
                        break;
                    }
                    size += 2;
                    let head = Term(*ptr);
                    if head.is_pointer() {
                        stack.push(head);
                    }
                    let tail = Term(*ptr.add(1));
                    if tail.bits() != (ptr as u64).wrapping_sub(16) | 1 {
                        term = tail;
                        break;
                    }
                    ptr = ptr.sub(2);
                }
            }
        }
        if term.bits() == ((&EMPTY_TUPLE as *const u64 as u64) | 2) {
            continue;
        }
        if let Some(h) = term.header() {
            if skip.skips(term.bits() & !7) {
                continue;
            }
            if preserve_sharing && unshared_literals.is_some_and(|l| l.is_literal(term.bits() & !7))
            {
                size += size_object(term);
                continue;
            }
            if preserve_sharing
                && (seen_before(term.bits() & !7) || !visited.insert(term.bits() & !7))
            {
                continue;
            }
            // SAFETY: term is live and its boxed header describes the allocation.
            let words = unsafe { crate::boxed_object_words(h, term.raw_ptr()) };
            size += words;
            stack.extend(children(term).filter(|child| child.is_pointer()));
        }
    }
    size
}
fn identity_cmp(a: Identity, b: Identity) -> Ordering {
    match (a, b) {
        (
            Identity::Pid {
                node: an,
                creation: ac,
                index: ai,
                serial: aser,
            },
            Identity::Pid {
                node: bn,
                creation: bc,
                index: bi,
                serial: bser,
            },
        ) => aser
            .cmp(&bser)
            .then(ai.cmp(&bi))
            .then(node_order(an, bn))
            .then(ac.cmp(&bc)),
        (
            Identity::Port {
                node: an,
                creation: ac,
                id: ai,
            },
            Identity::Port {
                node: bn,
                creation: bc,
                id: bi,
            },
        ) => node_order(an, bn).then(ac.cmp(&bc)).then(ai.cmp(&bi)),
        (
            Identity::Ref {
                node: an,
                creation: ac,
                mut ids,
            },
            Identity::Ref {
                node: bn,
                creation: bc,
                ids: mut other,
            },
        ) => {
            while ids.last() == Some(&0) && ids.len() > 1 {
                ids.pop();
            }
            while other.last() == Some(&0) && other.len() > 1 {
                other.pop();
            }
            node_order(an, bn)
                .then(ac.cmp(&bc))
                .then(ids.len().cmp(&other.len()))
                .then_with(|| ids.iter().rev().cmp(other.iter().rev()))
        }
        _ => Ordering::Equal,
    }
}
/// Alias for the number of words in a flattened copy.
pub fn flat_size(term: Term) -> usize {
    size_object(term)
}
/// Compare Erlang terms in term order. Port of `utils.c:1654` (`erts_cmp`),
/// OTP-29.1.1, for the implemented term classes.
#[inline]
pub fn cmp(a: Term, b: Term) -> Ordering {
    // Port of erts/emulator/beam/erl_utils.h (erts_cmp), OTP-29.1.1: atoms and small integers
    // are compared inline; everything else goes to the out-of-line erts_cmp_compound.
    if let (Some(x), Some(y)) = (a.as_atom(), b.as_atom()) {
        return if a == b {
            Ordering::Equal
        } else {
            global_atoms().cmp_atoms(x, y)
        };
    }
    if let (Some(x), Some(y)) = (a.as_small(), b.as_small()) {
        return x.cmp(&y);
    }
    cmp_impl(a, b, false)
}
/// Compare Erlang terms using exact numeric ordering, including nested terms.
///
/// This is the ordering used by `erts_internal:cmp_term/2` and map keys.
pub fn cmp_exact(a: Term, b: Term) -> Ordering {
    cmp_impl(a, b, true)
}
fn cmp_impl(a: Term, b: Term, exact: bool) -> Ordering {
    // Port of erts/emulator/beam/utils.c:1658-2735 (erts_cmp_compound), OTP-29.1.1.
    let mut pending = CmpStack::new();
    let (mut a, mut b, mut exact) = (a, b, exact);
    'term: loop {
        macro_rules! resolve_order {
            ($order:expr) => {{
                match pending.resume_result($order) {
                    CmpAction::Compare(left, right, next_exact) => {
                        a = left;
                        b = right;
                        exact = next_exact;
                        continue 'term;
                    }
                    CmpAction::Return(order) => return order,
                }
            }};
        }
        if a == b {
            match pending.resume_result(Ordering::Equal) {
                CmpAction::Compare(left, right, next_exact) => {
                    a = left;
                    b = right;
                    exact = next_exact;
                    continue 'term;
                }
                CmpAction::Return(order) => return order,
            }
        }

        // Port of the immediate fast paths in erts/emulator/beam/utils.c:1723-1739,
        // OTP-29.1.1. They also apply after a list or nested compound advances its pair.
        if let (Some(left), Some(right)) = (a.as_atom(), b.as_atom()) {
            resolve_order!(global_atoms().cmp_atoms(left, right));
        }
        if let (Some(left), Some(right)) = (a.as_small(), b.as_small()) {
            resolve_order!(left.cmp(&right));
        }
        // Port of the primary-list dispatch in erts/emulator/beam/utils.c:1827-1850,
        // OTP-29.1.1. Common list pairs stay in the tail-recursive path without classifying
        // both terms on every cons cell.
        if a.bits() & 3 == 1 {
            if b.bits() & 3 != 1 {
                resolve_order!(TermKind::List.cmp(&b.classify()));
            }
            // SAFETY: both list cells remain live on their owning heaps for this comparison.
            let (left_head, left_tail) = unsafe { a.cons_ref().unwrap() };
            // SAFETY: both list cells remain live on their owning heaps for this comparison.
            let (right_head, right_tail) = unsafe { b.cons_ref().unwrap() };
            if left_head != right_head {
                pending.push_terms(left_tail, right_tail, exact);
                a = left_head;
                b = right_head;
            } else {
                a = left_tail;
                b = right_tail;
            }
            continue 'term;
        }
        if b.bits() & 3 == 1 {
            resolve_order!(a.classify().cmp(&TermKind::List));
        }
        let ak = a.classify();
        let bk = b.classify();
        let c = ak.cmp(&bk);
        if c != Ordering::Equal {
            resolve_order!(c);
        }
        if ak == TermKind::Map {
            let size_order = crate::hamt::len(a).cmp(&crate::hamt::len(b));
            if size_order != Ordering::Equal {
                resolve_order!(size_order);
            }
            if a.is_hashmap() && b.is_hashmap() {
                match pending.start_hashmap(a, b, exact) {
                    CmpAction::Compare(left, right, next_exact) => {
                        a = left;
                        b = right;
                        exact = next_exact;
                        continue 'term;
                    }
                    CmpAction::Return(order) => resolve_order!(order),
                }
            } else {
                pending.start_flatmap(a, b, exact);
                a = b;
                continue 'term;
            }
        }
        let c = match ak {
            TermKind::Number => number_cmp(a, b, exact),
            TermKind::Atom => global_atoms().cmp_atoms(a.as_atom().unwrap(), b.as_atom().unwrap()),
            TermKind::Nil => Ordering::Equal,
            TermKind::Pid | TermKind::Port | TermKind::Ref => {
                identity_cmp(a.identity().unwrap(), b.identity().unwrap())
            }
            TermKind::List => unreachable!("list terms use the primary-tag fast path"),
            TermKind::Tuple => {
                // SAFETY: both tuples remain on their owning heaps.
                let av = unsafe { a.tuple_ref().unwrap() };
                // SAFETY: both tuples remain on their owning heaps.
                let bv = unsafe { b.tuple_ref().unwrap() };
                let c = av.len().cmp(&bv.len());
                if c != Ordering::Equal {
                    resolve_order!(c);
                }
                let left = CmpArray::Tuple(av);
                let right = CmpArray::Tuple(bv);
                match first_cmp_unequal(&left, &right, 0) {
                    Err(order) => resolve_order!(order),
                    Ok(None) => Ordering::Equal,
                    Ok(Some((index, left_term, right_term))) => {
                        let next = index + 1;
                        if next < left.len() {
                            pending.push_array(left, right, next, exact);
                        }
                        a = left_term;
                        b = right_term;
                        continue 'term;
                    }
                }
            }
            TermKind::Bitstring => bits_cmp(a, b),
            TermKind::Record => {
                // SAFETY: both record definitions and instances remain live.
                let av = unsafe { a.record_ref().unwrap() };
                // SAFETY: both record definitions and instances remain live.
                let bv = unsafe { b.record_ref().unwrap() };
                let c = node_order(av.module(), bv.module())
                    .then(node_order(av.name(), bv.name()))
                    .then(av.is_exported().cmp(&bv.is_exported()))
                    .then(av.len().cmp(&bv.len()));
                if c != Ordering::Equal {
                    resolve_order!(c);
                }
                // Port of erts/emulator/beam/erl_record.c:696-769, OTP-29.1.1.
                for i in 0..av.len() {
                    let ai = av.sorted_index(i).unwrap();
                    let bi = bv.sorted_index(i).unwrap();
                    let c = node_order(av.key(ai).unwrap(), bv.key(bi).unwrap());
                    if c != Ordering::Equal {
                        resolve_order!(c);
                    }
                }
                for i in (0..av.len()).rev() {
                    let ai = av.sorted_index(i).unwrap();
                    let bi = bv.sorted_index(i).unwrap();
                    pending.push_terms(av.value(ai).unwrap(), bv.value(bi).unwrap(), exact);
                }
                Ordering::Equal
            }
            TermKind::Fun => {
                // SAFETY: both owning heaps retain their fun entries.
                let av = unsafe { a.fun_ref().unwrap() };
                // SAFETY: both owning heaps retain their fun entries.
                let bv = unsafe { b.fun_ref().unwrap() };
                match (av, bv) {
                    (
                        FunRef::Local {
                            entry: ae,
                            free_vars: af,
                        },
                        FunRef::Local {
                            entry: be,
                            free_vars: bf,
                        },
                    ) => {
                        let c = node_order(ae.module, be.module)
                            .then(ae.index.cmp(&be.index))
                            .then(ae.old_uniq.cmp(&be.old_uniq))
                            .then(af.len().cmp(&bf.len()));
                        if c != Ordering::Equal {
                            resolve_order!(c);
                        }
                        let left = CmpArray::Words(af);
                        let right = CmpArray::Words(bf);
                        match first_cmp_unequal(&left, &right, 0) {
                            Err(order) => resolve_order!(order),
                            Ok(None) => Ordering::Equal,
                            Ok(Some((index, left_term, right_term))) => {
                                let next = index + 1;
                                if next < left.len() {
                                    pending.push_array(left, right, next, exact);
                                }
                                a = left_term;
                                b = right_term;
                                continue 'term;
                            }
                        }
                    }
                    (FunRef::Export { entry: ae }, FunRef::Export { entry: be }) => {
                        node_order(ae.module, be.module)
                            .then(node_order(ae.function, be.function))
                            .then(ae.arity.cmp(&be.arity))
                    }
                    (FunRef::Local { .. }, FunRef::Export { .. }) => Ordering::Less,
                    (FunRef::Export { .. }, FunRef::Local { .. }) => Ordering::Greater,
                }
            }
            TermKind::Map => unreachable!("maps are handled by the map work-stack paths"),
            _ => a.bits().cmp(&b.bits()),
        };
        if c != Ordering::Equal {
            resolve_order!(c);
        }
        a = b;
    }
}

enum CmpArray<'a> {
    Tuple(crate::TupleRef<'a>),
    Words(&'a [u64]),
    FlatmapKeys { map: Term, start: usize, len: usize },
}

impl CmpArray<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Tuple(tuple) => tuple.len(),
            Self::Words(words) => words.len(),
            Self::FlatmapKeys { len, .. } => *len,
        }
    }

    fn get(&self, index: usize) -> Option<Term> {
        match self {
            Self::Tuple(tuple) => tuple.get(index),
            Self::Words(words) => words.get(index).copied().map(Term),
            Self::FlatmapKeys { map, start, len } => {
                if index >= *len {
                    return None;
                }
                crate::hamt::with_flatmap_arrays(*map, |keys, _| Term(keys[*start + index]))
            }
        }
    }
}

struct CmpArrayPair<'a> {
    left: CmpArray<'a>,
    right: CmpArray<'a>,
}

enum CmpMapState {
    Hashmap,
    FlatmapAtomValues,
}

struct CmpHashmapState {
    left: crate::hamt::PairIter,
    right: crate::hamt::PairIter,
    ap: Option<(Term, Term)>,
    bp: Option<(Term, Term)>,
    cmp_res: Ordering,
    min_key: Option<Term>,
    was_exact: bool,
    rollback: usize,
    arrays_rollback: usize,
}

struct CmpFlatmapAtomValuesState {
    left_map: Term,
    right_map: Term,
    start: usize,
    count: usize,
    next_index: usize,
    current_key: Option<Term>,
    min_key: Option<Term>,
    cmp_res: Ordering,
    exact: bool,
    rollback: usize,
    arrays_rollback: usize,
}

enum CmpAction {
    Compare(Term, Term, bool),
    Return(Ordering),
}

// Port of the WSTACK work words in utils.c:1658-2735; typed array views are
// referenced by LIFO indices so the work stack never stores or dereferences raw pointers.
struct CmpStack<'a> {
    words: SmallVec<[u64; 16]>,
    arrays: Vec<CmpArrayPair<'a>>,
    maps: Vec<CmpMapState>,
    hashmaps: Vec<CmpHashmapState>,
    flatmap_atom_values: Vec<CmpFlatmapAtomValuesState>,
}

const WORK_OP_MASK: u64 = 0xF;
const CMP_EXACT_BIT: u64 = 1 << 6;
const CMP_TERM_OP: u64 = 2;
const CMP_ARRAY_OP: u64 = 3;
const CMP_FLATMAP_VALUES_OP: u64 = 4;
const CMP_FLATMAP_ATOM_KEYS_OP: u64 = 5;
const CMP_FLATMAP_ATOM_VALUES_START_OP: u64 = 6;
const CMP_FLATMAP_ATOM_VALUES_RESULT_OP: u64 = 7;
const CMP_HASHMAP_PHASE1_KEYS_OP: u64 = 8;
const CMP_HASHMAP_PHASE1_MIN_KEY_OP: u64 = 9;
const CMP_HASHMAP_PHASE1_VALUES_OP: u64 = 10;
const CMP_HASHMAP_PHASE2_KEYS_OP: u64 = 11;
const CMP_HASHMAP_PHASE2_MIN_LEFT_OP: u64 = 12;
const CMP_HASHMAP_PHASE2_MIN_RIGHT_OP: u64 = 13;

impl<'a> CmpStack<'a> {
    fn new() -> Self {
        Self {
            words: SmallVec::new(),
            arrays: Vec::new(),
            maps: Vec::new(),
            hashmaps: Vec::new(),
            flatmap_atom_values: Vec::new(),
        }
    }

    #[inline(always)]
    fn op_word(operation: u64, exact: bool) -> u64 {
        (operation << WORK_OP_SHIFT) | if exact { CMP_EXACT_BIT } else { 0 }
    }

    #[inline(always)]
    fn push_terms(&mut self, left: Term, right: Term, exact: bool) {
        self.words.push(right.bits());
        self.words.push(left.bits());
        self.words.push(Self::op_word(CMP_TERM_OP, exact));
    }

    #[inline(always)]
    fn push_array(&mut self, left: CmpArray<'a>, right: CmpArray<'a>, start: usize, exact: bool) {
        let index = self.arrays.len();
        self.arrays.push(CmpArrayPair { left, right });
        self.push_array_index(index, start, exact);
    }

    #[inline(always)]
    fn push_array_index(&mut self, index: usize, start: usize, exact: bool) {
        self.words.push(index as u64);
        self.words.push(start as u64);
        self.words.push(Self::op_word(CMP_ARRAY_OP, exact));
    }

    #[inline(always)]
    fn push_flatmap_values(
        &mut self,
        left_map: Term,
        right_map: Term,
        start: usize,
        end: usize,
        exact: bool,
    ) {
        self.words.push(right_map.bits());
        self.words.push(left_map.bits());
        self.words.push(start as u64);
        self.words.push(end as u64);
        self.words.push(Self::op_word(CMP_FLATMAP_VALUES_OP, exact));
    }

    #[inline(always)]
    fn push_flatmap_atom_values(
        &mut self,
        left_map: Term,
        right_map: Term,
        start: usize,
        remaining: usize,
        exact: bool,
    ) {
        if remaining == 0 {
            return;
        }
        self.words.push(right_map.bits());
        self.words.push(left_map.bits());
        self.words.push(start as u64);
        self.words.push(remaining as u64);
        self.words
            .push(Self::op_word(CMP_FLATMAP_ATOM_VALUES_START_OP, exact));
    }

    #[inline(always)]
    fn push_flatmap_atom_keys(
        &mut self,
        left_map: Term,
        right_map: Term,
        start: usize,
        count: usize,
    ) {
        if count == 0 {
            return;
        }
        self.words.push(right_map.bits());
        self.words.push(left_map.bits());
        self.words.push(start as u64);
        self.words.push(count as u64);
        self.words
            .push(Self::op_word(CMP_FLATMAP_ATOM_KEYS_OP, true));
    }

    #[inline(always)]
    fn push_map_operation(&mut self, operation: u64, exact: bool) {
        self.words.push(Self::op_word(operation, exact));
        let rollback = self.words.len();
        let arrays_rollback = self.arrays.len();
        match self.maps.last().expect("map work state is present") {
            CmpMapState::Hashmap => {
                let state = self.hashmaps.last_mut().expect("hashmap state is present");
                state.rollback = rollback;
                state.arrays_rollback = arrays_rollback;
            }
            CmpMapState::FlatmapAtomValues => {
                let state = self
                    .flatmap_atom_values
                    .last_mut()
                    .expect("flatmap atom value state is present");
                state.rollback = rollback;
                state.arrays_rollback = arrays_rollback;
            }
        }
    }

    // Port of erts/emulator/beam/utils.c:2080-2122 (hashmap compare setup), OTP-29.1.1.
    fn start_hashmap(&mut self, left_map: Term, right_map: Term, exact: bool) -> CmpAction {
        let mut left = crate::hamt::PairIter::new(left_map);
        let mut right = crate::hamt::PairIter::new(right_map);
        let ap = left.next();
        let bp = right.next();
        let (Some((left_key, _)), Some((right_key, _))) = (ap, bp) else {
            return CmpAction::Return(Ordering::Equal);
        };
        self.hashmaps.push(CmpHashmapState {
            left,
            right,
            ap,
            bp,
            cmp_res: Ordering::Equal,
            min_key: None,
            was_exact: exact,
            rollback: 0,
            arrays_rollback: self.arrays.len(),
        });
        self.maps.push(CmpMapState::Hashmap);
        self.push_map_operation(CMP_HASHMAP_PHASE1_KEYS_OP, true);
        CmpAction::Compare(left_key, right_key, true)
    }

    // Port of erts/emulator/beam/utils.c:1989-2104 (flatmap compare phases), OTP-29.1.1.
    fn start_flatmap(&mut self, left_map: Term, right_map: Term, exact: bool) {
        crate::hamt::with_flatmap_arrays(left_map, |left_keys, _| {
            crate::hamt::with_flatmap_arrays(right_map, |right_keys, _| {
                let len = left_keys.len();
                if exact {
                    if len != 0 {
                        self.push_flatmap_values(left_map, right_map, 0, len, exact);
                        self.push_array(
                            CmpArray::FlatmapKeys {
                                map: left_map,
                                start: 0,
                                len,
                            },
                            CmpArray::FlatmapKeys {
                                map: right_map,
                                start: 0,
                                len,
                            },
                            0,
                            true,
                        );
                    }
                    return;
                }

                let mut split = 0;
                while split < len
                    && !(Term(left_keys[split]).as_atom().is_some()
                        && Term(right_keys[split]).as_atom().is_some())
                {
                    split += 1;
                }
                let number_end = split;
                while split < len
                    && (Term(left_keys[split]).as_atom().is_some()
                        || Term(right_keys[split]).as_atom().is_some())
                {
                    split += 1;
                }
                let atom_end = split;
                let atom_count = atom_end - number_end;

                if atom_end < len {
                    self.push_flatmap_values(left_map, right_map, atom_end, len, exact);
                }
                self.push_flatmap_atom_values(left_map, right_map, number_end, atom_count, exact);
                if number_end != 0 {
                    self.push_flatmap_values(left_map, right_map, 0, number_end, exact);
                }

                if atom_end < len {
                    self.push_array(
                        CmpArray::FlatmapKeys {
                            map: left_map,
                            start: atom_end,
                            len: len - atom_end,
                        },
                        CmpArray::FlatmapKeys {
                            map: right_map,
                            start: atom_end,
                            len: len - atom_end,
                        },
                        0,
                        true,
                    );
                }
                self.push_flatmap_atom_keys(left_map, right_map, number_end, atom_count);
                if number_end != 0 {
                    self.push_array(
                        CmpArray::FlatmapKeys {
                            map: left_map,
                            start: 0,
                            len: number_end,
                        },
                        CmpArray::FlatmapKeys {
                            map: right_map,
                            start: 0,
                            len: number_end,
                        },
                        0,
                        true,
                    );
                }
            })
            .expect("right map is a live flatmap");
        })
        .expect("left map is a live flatmap");
    }

    // Port of pop_next and not_equal rollback in utils.c:2493-2745, OTP-29.1.1.
    fn resume_result(&mut self, mut result: Ordering) -> CmpAction {
        loop {
            if result != Ordering::Equal {
                let Some(state) = self.maps.last() else {
                    return CmpAction::Return(result);
                };
                let (rollback, arrays_rollback) = match state {
                    CmpMapState::Hashmap => {
                        let state = self.hashmaps.last().expect("hashmap state is present");
                        (state.rollback, state.arrays_rollback)
                    }
                    CmpMapState::FlatmapAtomValues => {
                        let state = self
                            .flatmap_atom_values
                            .last()
                            .expect("flatmap atom value state is present");
                        (state.rollback, state.arrays_rollback)
                    }
                };
                self.words.truncate(rollback);
                self.arrays.truncate(arrays_rollback);
            }

            let Some(word) = self.words.pop() else {
                return CmpAction::Return(result);
            };
            let operation = (word >> WORK_OP_SHIFT) & WORK_OP_MASK;
            let exact = word & CMP_EXACT_BIT != 0;
            let action = match operation {
                CMP_TERM_OP => {
                    let left = Term(self.words.pop().expect("left term is present"));
                    let right = Term(self.words.pop().expect("right term is present"));
                    return CmpAction::Compare(left, right, exact);
                }
                CMP_ARRAY_OP => self.resume_array(exact),
                CMP_FLATMAP_VALUES_OP => self.resume_flatmap_values(exact),
                CMP_FLATMAP_ATOM_KEYS_OP => self.resume_flatmap_atom_keys(),
                CMP_FLATMAP_ATOM_VALUES_START_OP => self.start_flatmap_atom_values(exact),
                CMP_FLATMAP_ATOM_VALUES_RESULT_OP => self.resume_flatmap_atom_values(result),
                CMP_HASHMAP_PHASE1_KEYS_OP
                | CMP_HASHMAP_PHASE1_MIN_KEY_OP
                | CMP_HASHMAP_PHASE1_VALUES_OP
                | CMP_HASHMAP_PHASE2_KEYS_OP
                | CMP_HASHMAP_PHASE2_MIN_LEFT_OP
                | CMP_HASHMAP_PHASE2_MIN_RIGHT_OP => self.resume_hashmap(operation, result),
                _ => unreachable!("invalid comparison work word"),
            };
            match action {
                CmpAction::Compare(left, right, next_exact) => {
                    return CmpAction::Compare(left, right, next_exact);
                }
                CmpAction::Return(next_result) => result = next_result,
            }
        }
    }

    fn resume_array(&mut self, exact: bool) -> CmpAction {
        let start = self.words.pop().expect("array start is present") as usize;
        let array_index = self.words.pop().expect("array handle is present") as usize;
        let (result, len) = {
            let pair = &self.arrays[array_index];
            (
                first_cmp_unequal(&pair.left, &pair.right, start),
                pair.left.len(),
            )
        };
        match result {
            Err(order) => CmpAction::Return(order),
            Ok(None) => {
                self.arrays.truncate(array_index);
                CmpAction::Return(Ordering::Equal)
            }
            Ok(Some((index, left, right))) => {
                let next = index + 1;
                if next < len {
                    self.push_array_index(array_index, next, exact);
                } else {
                    self.arrays.truncate(array_index);
                }
                CmpAction::Compare(left, right, exact)
            }
        }
    }

    fn resume_flatmap_values(&mut self, exact: bool) -> CmpAction {
        let end = self.words.pop().expect("array end is present") as usize;
        let start = self.words.pop().expect("array start is present") as usize;
        let left_map = Term(self.words.pop().expect("left map is present"));
        let right_map = Term(self.words.pop().expect("right map is present"));
        match first_cmp_flatmap_values(left_map, right_map, start, end, exact, self) {
            Err(order) => CmpAction::Return(order),
            Ok(None) => CmpAction::Return(Ordering::Equal),
            Ok(Some((left, right))) => CmpAction::Compare(left, right, exact),
        }
    }

    fn resume_flatmap_atom_keys(&mut self) -> CmpAction {
        let count = self.words.pop().expect("atom count is present") as usize;
        let start = self.words.pop().expect("array start is present") as usize;
        let left_map = Term(self.words.pop().expect("left map is present"));
        let right_map = Term(self.words.pop().expect("right map is present"));
        let order = crate::hamt::with_flatmap_arrays(left_map, |left_keys, _| {
            crate::hamt::with_flatmap_arrays(right_map, |right_keys, _| {
                flatmap_atom_key_cmp(left_keys, right_keys, start, count)
            })
            .expect("right map is a live flatmap")
        })
        .expect("left map is a live flatmap");
        CmpAction::Return(order)
    }

    fn start_flatmap_atom_values(&mut self, exact: bool) -> CmpAction {
        let count = self.words.pop().expect("atom count is present") as usize;
        let start = self.words.pop().expect("array start is present") as usize;
        let left_map = Term(self.words.pop().expect("left map is present"));
        let right_map = Term(self.words.pop().expect("right map is present"));
        self.flatmap_atom_values.push(CmpFlatmapAtomValuesState {
            left_map,
            right_map,
            start,
            count,
            next_index: start,
            current_key: None,
            min_key: None,
            cmp_res: Ordering::Equal,
            exact,
            rollback: 0,
            arrays_rollback: self.arrays.len(),
        });
        self.maps.push(CmpMapState::FlatmapAtomValues);
        self.start_next_flatmap_atom_value()
    }

    fn resume_flatmap_atom_values(&mut self, result: Ordering) -> CmpAction {
        if result != Ordering::Equal {
            if !matches!(self.maps.last(), Some(CmpMapState::FlatmapAtomValues)) {
                unreachable!("flatmap atom value state is present");
            }
            let state = self
                .flatmap_atom_values
                .last_mut()
                .expect("flatmap atom value state is present");
            state.min_key = state.current_key;
            state.cmp_res = result;
        }
        self.start_next_flatmap_atom_value()
    }

    // Port of FLATMAP_ATOM_VALUES in utils.c:2672-2717, OTP-29.1.1.
    fn start_next_flatmap_atom_value(&mut self) -> CmpAction {
        let (left_map, right_map, end, mut index, min_key, exact) = {
            let Some(state) = self.flatmap_atom_values.last() else {
                unreachable!("flatmap atom value state is present");
            };
            (
                state.left_map,
                state.right_map,
                state.start + state.count,
                state.next_index,
                state.min_key,
                state.exact,
            )
        };
        let mut found = None;
        crate::hamt::with_flatmap_arrays(left_map, |keys, _| {
            while index < end {
                let key = Term(keys[index]);
                let atom = key.as_atom().expect("atom partition contains atoms");
                let eligible = min_key.is_none_or(|current| {
                    global_atoms().cmp_atoms(atom, current.as_atom().unwrap()) == Ordering::Less
                });
                let current = index;
                index += 1;
                if eligible {
                    found = Some((current, key));
                    break;
                }
            }
        })
        .expect("left map is a live flatmap");
        let Some((value_index, key)) = found else {
            let Some(CmpMapState::FlatmapAtomValues) = self.maps.pop() else {
                unreachable!("flatmap atom value state is present");
            };
            let cmp_res = self.flatmap_atom_values.pop().unwrap().cmp_res;
            return CmpAction::Return(cmp_res);
        };
        let (left_value, right_value) =
            crate::hamt::with_flatmap_arrays(left_map, |_, left_values| {
                crate::hamt::with_flatmap_arrays(right_map, |_, right_values| {
                    (
                        Term(left_values[value_index]),
                        Term(right_values[value_index]),
                    )
                })
                .expect("right map is a live flatmap")
            })
            .expect("left map is a live flatmap");
        let state = self
            .flatmap_atom_values
            .last_mut()
            .expect("flatmap atom value state is present");
        state.next_index = index;
        state.current_key = Some(key);
        self.push_map_operation(CMP_FLATMAP_ATOM_VALUES_RESULT_OP, exact);
        CmpAction::Compare(left_value, right_value, exact)
    }

    // Port of the HASHMAP_PHASE1/2 operations in utils.c:2511-2665, OTP-29.1.1.
    fn resume_hashmap(&mut self, operation: u64, result: Ordering) -> CmpAction {
        match operation {
            CMP_HASHMAP_PHASE1_KEYS_OP => {
                if result != Ordering::Equal {
                    let state = self.hashmaps.last().expect("hashmap state is present");
                    let hash_order = hashmap_key_hash_order(
                        state.ap.map(|pair| pair.0),
                        state.bp.map(|pair| pair.0),
                    );
                    let side = if hash_order == Ordering::Equal {
                        result
                    } else {
                        hash_order
                    };
                    let state = self.hashmaps.last_mut().expect("hashmap state is present");
                    if side == Ordering::Less {
                        state.min_key = state.ap.map(|pair| pair.0);
                        state.cmp_res = Ordering::Less;
                        state.ap = state.left.next();
                    } else {
                        state.min_key = state.bp.map(|pair| pair.0);
                        state.cmp_res = Ordering::Greater;
                        state.bp = state.right.next();
                    }
                    self.start_hashmap_phase2()
                } else {
                    let state = self.hashmaps.last().expect("hashmap state is present");
                    let candidate = (state.cmp_res != Ordering::Equal)
                        .then_some(state.min_key)
                        .flatten();
                    let was_exact = state.was_exact;
                    if let Some(min_key) = candidate {
                        let ap_key = self.hashmap_current_left_key();
                        self.push_map_operation(CMP_HASHMAP_PHASE1_MIN_KEY_OP, true);
                        CmpAction::Compare(ap_key, min_key, true)
                    } else {
                        let (left_value, right_value) = self.hashmap_current_values();
                        self.push_map_operation(CMP_HASHMAP_PHASE1_VALUES_OP, was_exact);
                        CmpAction::Compare(left_value, right_value, was_exact)
                    }
                }
            }
            CMP_HASHMAP_PHASE1_MIN_KEY_OP => {
                if result == Ordering::Less {
                    let (left_value, right_value) = self.hashmap_current_values();
                    let was_exact = self.hashmap_was_exact();
                    self.push_map_operation(CMP_HASHMAP_PHASE1_VALUES_OP, was_exact);
                    CmpAction::Compare(left_value, right_value, was_exact)
                } else {
                    self.advance_hashmap_phase1()
                }
            }
            CMP_HASHMAP_PHASE1_VALUES_OP => {
                if result != Ordering::Equal {
                    let left_key = self.hashmap_current_left_key();
                    let state = self.hashmaps.last_mut().expect("hashmap state is present");
                    state.cmp_res = result;
                    state.min_key = Some(left_key);
                }
                let state = self.hashmaps.last_mut().expect("hashmap state is present");
                state.ap = state.left.next();
                state.bp = state.right.next();
                self.start_hashmap_phase1()
            }
            CMP_HASHMAP_PHASE2_KEYS_OP => {
                if result == Ordering::Equal {
                    let state = self.hashmaps.last_mut().expect("hashmap state is present");
                    state.ap = state.left.next();
                    state.bp = state.right.next();
                    self.start_hashmap_phase2()
                } else {
                    self.hashmap_phase2_next(result)
                }
            }
            CMP_HASHMAP_PHASE2_MIN_LEFT_OP => {
                if result == Ordering::Less {
                    let left_key = self.hashmap_current_left_key();
                    let state = self.hashmaps.last_mut().expect("hashmap state is present");
                    state.cmp_res = Ordering::Less;
                    state.min_key = Some(left_key);
                }
                let state = self.hashmaps.last_mut().expect("hashmap state is present");
                state.ap = state.left.next();
                self.start_hashmap_phase2()
            }
            CMP_HASHMAP_PHASE2_MIN_RIGHT_OP => {
                if result == Ordering::Less {
                    let right_key = self.hashmap_current_right_key();
                    let state = self.hashmaps.last_mut().expect("hashmap state is present");
                    state.cmp_res = Ordering::Greater;
                    state.min_key = Some(right_key);
                }
                let state = self.hashmaps.last_mut().expect("hashmap state is present");
                state.bp = state.right.next();
                self.start_hashmap_phase2()
            }
            _ => unreachable!("invalid hashmap comparison operation"),
        }
    }

    fn hashmap_current_left_key(&self) -> Term {
        let Some(pair) = self.hashmaps.last().and_then(|state| state.ap) else {
            unreachable!("left hashmap entry is present");
        };
        pair.0
    }

    fn hashmap_current_right_key(&self) -> Term {
        let Some(pair) = self.hashmaps.last().and_then(|state| state.bp) else {
            unreachable!("right hashmap entry is present");
        };
        pair.0
    }

    fn hashmap_current_values(&self) -> (Term, Term) {
        let Some((left, right)) = self
            .hashmaps
            .last()
            .and_then(|state| state.ap.zip(state.bp))
        else {
            unreachable!("both hashmap entries are present");
        };
        (left.1, right.1)
    }

    fn hashmap_was_exact(&self) -> bool {
        self.hashmaps
            .last()
            .expect("hashmap state is present")
            .was_exact
    }

    fn start_hashmap_phase1(&mut self) -> CmpAction {
        let state = self.hashmaps.last().expect("hashmap state is present");
        let (left_key, right_key) = match (state.ap, state.bp) {
            (Some(left), Some(right)) => (left.0, right.0),
            (None, None) => {
                let order = state.cmp_res;
                self.hashmaps.pop();
                assert!(matches!(self.maps.pop(), Some(CmpMapState::Hashmap)));
                return CmpAction::Return(order);
            }
            _ => unreachable!("hashmap iterators advance together in phase one"),
        };
        self.push_map_operation(CMP_HASHMAP_PHASE1_KEYS_OP, true);
        CmpAction::Compare(left_key, right_key, true)
    }

    fn advance_hashmap_phase1(&mut self) -> CmpAction {
        let state = self.hashmaps.last_mut().expect("hashmap state is present");
        state.ap = state.left.next();
        state.bp = state.right.next();
        self.start_hashmap_phase1()
    }

    fn start_hashmap_phase2(&mut self) -> CmpAction {
        match self.hashmaps.last().unwrap() {
            state if state.ap.zip(state.bp).is_some() => {
                let (left, right) = state.ap.zip(state.bp).unwrap();
                self.push_map_operation(CMP_HASHMAP_PHASE2_KEYS_OP, true);
                CmpAction::Compare(left.0, right.0, true)
            }
            _ => self.hashmap_phase2_next(Ordering::Equal),
        }
    }

    fn hashmap_phase2_next(&mut self, key_order: Ordering) -> CmpAction {
        let (left_pair, right_pair, min_key) = {
            let state = self.hashmaps.last().expect("hashmap state is present");
            (state.ap, state.bp, state.min_key)
        };
        if left_pair.is_none() && right_pair.is_none() {
            let cmp_res = self.hashmaps.pop().unwrap().cmp_res;
            assert!(matches!(self.maps.pop(), Some(CmpMapState::Hashmap)));
            return CmpAction::Return(cmp_res);
        }
        let hash_order =
            hashmap_key_hash_order(left_pair.map(|pair| pair.0), right_pair.map(|pair| pair.0));
        let side = if hash_order == Ordering::Equal {
            match (left_pair, right_pair) {
                (Some(_), Some(_)) => key_order,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => unreachable!(),
            }
        } else {
            hash_order
        };
        if side == Ordering::Less {
            let (Some((left_key, _)), Some(min_key)) = (left_pair, min_key) else {
                unreachable!("left key and minimum key are present");
            };
            self.push_map_operation(CMP_HASHMAP_PHASE2_MIN_LEFT_OP, true);
            CmpAction::Compare(left_key, min_key, true)
        } else {
            let (Some((right_key, _)), Some(min_key)) = (right_pair, min_key) else {
                unreachable!("right key and minimum key are present");
            };
            self.push_map_operation(CMP_HASHMAP_PHASE2_MIN_RIGHT_OP, true);
            CmpAction::Compare(right_key, min_key, true)
        }
    }
}

// Port of erts/emulator/beam/utils.c:2468-2486 (TERM_ARRAY_OP), OTP-29.1.1.
fn first_cmp_unequal(
    left: &CmpArray<'_>,
    right: &CmpArray<'_>,
    start: usize,
) -> Result<Option<(usize, Term, Term)>, Ordering> {
    for index in start..left.len() {
        let a = left.get(index).expect("array index is in range");
        let b = right
            .get(index)
            .expect("equal-length array index is in range");
        if a == b {
            continue;
        }
        if let (Some(a), Some(b)) = (a.as_small(), b.as_small()) {
            let order = a.cmp(&b);
            if order != Ordering::Equal {
                return Err(order);
            }
            continue;
        }
        if let (Some(a), Some(b)) = (a.as_atom(), b.as_atom()) {
            let order = global_atoms().cmp_atoms(a, b);
            if order != Ordering::Equal {
                return Err(order);
            }
            continue;
        }
        return Ok(Some((index, a, b)));
    }
    Ok(None)
}

// Port of the flatmap value-array continuation in erts_cmp_compound
// (erts/emulator/beam/utils.c:2046-2066), OTP-29.1.1.
fn first_cmp_flatmap_values(
    left_map: Term,
    right_map: Term,
    start: usize,
    end: usize,
    exact: bool,
    pending: &mut CmpStack<'_>,
) -> Result<Option<(Term, Term)>, Ordering> {
    let result = crate::hamt::with_flatmap_arrays(left_map, |_, left_values| {
        crate::hamt::with_flatmap_arrays(right_map, |_, right_values| {
            first_cmp_unequal(
                &CmpArray::Words(&left_values[..end]),
                &CmpArray::Words(&right_values[..end]),
                start,
            )
        })
        .expect("right map is a live flatmap")
    })
    .expect("left map is a live flatmap")?;
    let Some((index, left_term, right_term)) = result else {
        return Ok(None);
    };
    let next = index + 1;
    if next < end {
        pending.push_flatmap_values(left_map, right_map, next, end, exact);
    }
    Ok(Some((left_term, right_term)))
}

// Port of erts/emulator/beam/utils.c:1536-1625 (compare_flatmap_atom_keys), OTP-29.1.1.
fn flatmap_atom_key_cmp(
    left_keys: &[u64],
    right_keys: &[u64],
    start: usize,
    count: usize,
) -> Ordering {
    fn atom_at(keys: &[u64], index: usize, remaining: usize) -> Option<Term> {
        if remaining == 0 {
            return None;
        }
        let key = Term(keys[index]);
        key.as_atom().map(|_| key)
    }

    let mut left_index = start;
    let mut right_index = start;
    let mut left_remaining = count;
    let mut right_remaining = count;
    let mut minimum: Option<(crate::Atom, Ordering)> = None;
    let mut left_key = atom_at(left_keys, left_index, left_remaining);
    let mut right_key = atom_at(right_keys, right_index, right_remaining);
    while left_key.is_some() && left_key == right_key {
        left_remaining -= 1;
        right_remaining -= 1;
        if left_remaining == 0 {
            return Ordering::Equal;
        }
        left_index += 1;
        right_index += 1;
        left_key = atom_at(left_keys, left_index, left_remaining);
        right_key = atom_at(right_keys, right_index, right_remaining);
    }
    loop {
        let left_atom = left_key.and_then(Term::as_atom);
        let right_atom = right_key.and_then(Term::as_atom);
        let (candidate, side) = match (left_atom, right_atom) {
            (None, None) => break,
            (Some(left_atom), Some(right_atom)) if left_atom == right_atom => {
                left_remaining -= 1;
                right_remaining -= 1;
                left_index += 1;
                right_index += 1;
                left_key = atom_at(left_keys, left_index, left_remaining);
                right_key = atom_at(right_keys, right_index, right_remaining);
                continue;
            }
            (Some(left_atom), Some(_)) if left_key.unwrap().bits() < right_key.unwrap().bits() => {
                left_remaining -= 1;
                left_index += 1;
                left_key = atom_at(left_keys, left_index, left_remaining);
                (left_atom, Ordering::Less)
            }
            (Some(_), Some(right_atom)) => {
                right_remaining -= 1;
                right_index += 1;
                right_key = atom_at(right_keys, right_index, right_remaining);
                (right_atom, Ordering::Greater)
            }
            (Some(atom), None) => {
                left_remaining -= 1;
                left_index += 1;
                left_key = atom_at(left_keys, left_index, left_remaining);
                (atom, Ordering::Less)
            }
            (None, Some(atom)) => {
                right_remaining -= 1;
                right_index += 1;
                right_key = atom_at(right_keys, right_index, right_remaining);
                (atom, Ordering::Greater)
            }
        };
        if minimum.is_none_or(|(current, _)| {
            global_atoms().cmp_atoms(candidate, current) == Ordering::Less
        }) {
            minimum = Some((candidate, side));
        }
    }
    minimum.map_or(Ordering::Equal, |(_, side)| side)
}

// Port of erts/emulator/beam/erl_map.c:1881-1898 (hashmap_key_hash_cmp/hash_cmp), OTP-29.1.1.
fn hashmap_key_hash_order(left: Option<Term>, right: Option<Term>) -> Ordering {
    match (left, right) {
        (Some(left), Some(right)) => {
            let (mut left_hash, mut right_hash) =
                (crate::internal_hash(left), crate::internal_hash(right));
            for _ in 0..16 {
                let order = (left_hash & 0xF).cmp(&(right_hash & 0xF));
                if order != Ordering::Equal {
                    return order;
                }
                left_hash >>= 4;
                right_hash >>= 4;
            }
            Ordering::Equal
        }
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn exact_number_eq(a: Term, b: Term) -> bool {
    match (a.as_small(), b.as_small()) {
        (Some(x), Some(y)) => return x == y,
        (Some(_), None) | (None, Some(_)) => return false,
        _ => {}
    }
    let (ah, bh) = (a.header().unwrap(), b.header().unwrap());
    if ah & 63 != bh & 63 {
        return false;
    }
    // SAFETY: both numeric headers describe initialized, live payload words.
    unsafe {
        let (ap, bp) = (a.raw_ptr(), b.raw_ptr());
        let words = 1 + (ah >> 6) as usize;
        ah == bh
            && std::slice::from_raw_parts(ap.add(1), words - 1)
                == std::slice::from_raw_parts(bp.add(1), words - 1)
    }
}
fn exact_ref_eq(a: Term, b: Term) -> bool {
    // Port of erts/emulator/beam/utils.c:1325-1355 (reference equality), OTP-29.1.1.
    fn fields(term: Term) -> (crate::Atom, u32, [u32; 5], usize) {
        let header = term.header().unwrap();
        // SAFETY: a live reference's header identifies its initialized words.
        let ptr = unsafe { term.raw_ptr() };
        let mut ids = [0; 5];
        let (node, creation, len) = match header & 63 {
            crate::REF => {
                // Ordinary and magic refs share the header; internal_ref_numbers picks the
                // ErtsORefThing numbers or the magic binary's refn.
                let numbers = term
                    .local_ref_numbers()
                    .or_else(|| term.magic_ref_numbers())
                    .unwrap();
                ids[..3].copy_from_slice(&numbers);
                (crate::atoms::NONAME, 0, 3)
            }
            crate::EXTERNAL_REF => {
                // SAFETY: the external-ref payload retains the Node and stores its id count.
                let node = unsafe { &*(*ptr.add(1) as *const crate::Node) };
                // SAFETY: the live reference header bounds its count and packed ids.
                let count = unsafe {
                    let count = (*ptr.add(3) as u32) as usize;
                    for (i, id) in ids.iter_mut().enumerate().take(count) {
                        let index = i + 1;
                        let word = *ptr.add(3 + index / 2);
                        *id = if index % 2 == 0 {
                            word as u32
                        } else {
                            (word >> 32) as u32
                        };
                    }
                    count
                };
                (node.name, node.creation, count)
            }
            _ => unreachable!(),
        };
        (node, creation, ids, len)
    }
    let (an, ac, ai, mut al) = fields(a);
    let (bn, bc, bi, mut bl) = fields(b);
    while al > 1 && ai[al - 1] == 0 {
        al -= 1;
    }
    while bl > 1 && bi[bl - 1] == 0 {
        bl -= 1;
    }
    node_order(an, bn) == Ordering::Equal && ac == bc && ai[..al] == bi[..bl]
}
/// Erlang `=:=` for implemented types. Signed zero compares by bit pattern.
#[inline]
pub fn exact_eq(a: Term, b: Term) -> bool {
    // Port of erts/emulator/beam/erl_utils.h:113 (EQ), OTP-29.1.1.
    a == b || (!both_immed(a, b) && eq(a, b))
}

/// Run `eq` after a caller's raw-word check, as `lists_member_2` does.
// Port of `erl_bif_lists.c:1132`, OTP-29.1.1.
#[inline(always)]
pub fn exact_eq_after_word_mismatch(a: Term, b: Term) -> bool {
    eq(a, b)
}

// Port of `is_both_immed` in erts/emulator/beam/erl_term.h:184, OTP-29.1.1.
#[inline(always)]
fn both_immed(a: Term, b: Term) -> bool {
    Term(a.0 & b.0).is_immed()
}

fn exact_eq_mixed_map_layouts(left: Term, right: Term) -> Option<Vec<(Term, Term)>> {
    let mut values = Vec::with_capacity(crate::hamt::len(left));
    for (key, value) in crate::hamt::PairIter::new(left) {
        let (_, right_value) = crate::hamt::PairIter::new(right)
            .find(|(right_key, _)| cmp_impl(key, *right_key, true) == Ordering::Equal)?;
        values.push((value, right_value));
    }
    Some(values)
}

// Port of erts/emulator/beam/utils.c:1488-1523 (eq's term_array continuation), OTP-29.1.1.
enum EqArray<'a> {
    Tuple(crate::TupleRef<'a>),
    Words(&'a [u64]),
}

impl EqArray<'_> {
    fn len(&self) -> usize {
        match self {
            Self::Tuple(tuple) => tuple.len(),
            Self::Words(words) => words.len(),
        }
    }

    fn get(&self, index: usize) -> Option<Term> {
        match self {
            Self::Tuple(tuple) => tuple.get(index),
            Self::Words(words) => words.get(index).copied().map(Term),
        }
    }
}

struct EqArrayPair<'a> {
    left: EqArray<'a>,
    right: EqArray<'a>,
}

struct EqHashmapIterPair {
    left: crate::hamt::PairIter,
    right: crate::hamt::PairIter,
}

// Port of WSTACK's 16-word inline representation in erts/emulator/beam/global.h,
// OTP-29.1.1. Borrowed views and iterators stay typed here; their LIFO handles are words.
struct EqStack<'a> {
    words: SmallVec<[u64; 16]>,
    arrays: SmallVec<[EqArrayPair<'a>; 5]>,
    hashmaps: Vec<EqHashmapIterPair>,
}

impl<'a> EqStack<'a> {
    fn new() -> Self {
        Self {
            words: SmallVec::new(),
            arrays: SmallVec::new(),
            hashmaps: Vec::new(),
        }
    }

    #[inline(always)]
    fn push_terms(&mut self, left: Term, right: Term) {
        self.words.push(right.bits());
        self.words.push(left.bits());
    }

    #[inline(always)]
    fn push_array(&mut self, left: EqArray<'a>, right: EqArray<'a>, start: usize) {
        let index = self.arrays.len();
        self.arrays.push(EqArrayPair { left, right });
        self.push_array_index(index, start);
    }

    #[inline(always)]
    fn push_array_index(&mut self, index: usize, start: usize) {
        self.words.push(index as u64);
        self.words.push(start as u64);
        self.words.push(eq_array_op());
    }

    #[inline(always)]
    fn push_flatmap_values(&mut self, left: Term, right: Term, start: usize, end: usize) {
        self.words.push(right.bits());
        self.words.push(left.bits());
        self.words.push(start as u64);
        self.words.push(end as u64);
        self.words.push(eq_flatmap_values_op());
    }

    #[inline(always)]
    fn push_hashmap(&mut self, left: Term, right: Term) {
        let index = self.hashmaps.len();
        self.hashmaps.push(EqHashmapIterPair {
            left: crate::hamt::PairIter::new(left),
            right: crate::hamt::PairIter::new(right),
        });
        self.push_hashmap_index(index);
    }

    #[inline(always)]
    fn push_hashmap_index(&mut self, index: usize) {
        self.words.push(index as u64);
        self.words.push(eq_hashmap_op());
    }
}

const WORK_OP_SHIFT: u32 = 2;
const EQ_ARRAY_OP: u64 = 1;
const EQ_FLATMAP_VALUES_OP: u64 = 2;
const EQ_HASHMAP_OP: u64 = 3;

// Port of `primary_tag` and boxed-header dispatch in utils.c:1133-1190,
// OTP-29.1.1. Matching the peer header here avoids classifying both terms.
#[inline(always)]
fn eq_kind_from_header(header: u64) -> Option<TermKind> {
    Some(match header & 63 {
        ARITY => TermKind::Tuple,
        POS_BIG | NEG_BIG | FLOAT => TermKind::Number,
        REF | EXTERNAL_REF => TermKind::Ref,
        FUN => TermKind::Fun,
        EXTERNAL_PORT => TermKind::Port,
        EXTERNAL_PID => TermKind::Pid,
        RECORD => TermKind::Record,
        MAP => TermKind::Map,
        HEAP_BITS | SUB_BITS => TermKind::Bitstring,
        BIN_REF => TermKind::BinRef,
        _ => return None,
    })
}

#[inline(always)]
fn eq_compound_kind(a: Term, b: Term) -> Option<TermKind> {
    match a.0 & 3 {
        1 if b.0 & 3 == 1 => Some(TermKind::List),
        2 if b.0 & 3 == 2 => {
            let header = a.header()?;
            let kind = eq_kind_from_header(header)?;
            if matches!(kind, TermKind::Tuple | TermKind::Record | TermKind::Number) {
                return (b.header()? == header).then_some(kind);
            }
            (eq_kind_from_header(b.header()?)? == kind).then_some(kind)
        }
        _ => None,
    }
}

// Port of the operation words tagged as TAG_PRIMARY_HEADER in utils.c:1488-1510.
#[inline(always)]
const fn eq_array_op() -> u64 {
    EQ_ARRAY_OP << WORK_OP_SHIFT
}

#[inline(always)]
const fn eq_flatmap_values_op() -> u64 {
    EQ_FLATMAP_VALUES_OP << WORK_OP_SHIFT
}

#[inline(always)]
const fn eq_hashmap_op() -> u64 {
    EQ_HASHMAP_OP << WORK_OP_SHIFT
}

#[inline(always)]
const fn is_work_op(word: u64) -> bool {
    word & 3 == 0
}

fn first_unequal(
    left: &EqArray<'_>,
    right: &EqArray<'_>,
    start: usize,
) -> Option<(usize, Term, Term)> {
    for index in start..left.len() {
        let a = left.get(index).expect("array index is in range");
        let b = right
            .get(index)
            .expect("equal-length array index is in range");
        if a != b {
            return Some((index, a, b));
        }
    }
    None
}

/// Port of erts/emulator/beam/utils.c:1125-1530 (eq), OTP-29.1.1.
#[inline(never)]
fn eq(a: Term, b: Term) -> bool {
    let mut pending: Option<EqStack<'_>> = None;
    let (mut a, mut b) = (a, b);
    'term: loop {
        if a == b {
            let Some(stack) = pending.as_mut() else {
                return true;
            };
            let Some(word) = stack.words.pop() else {
                return true;
            };
            if !is_work_op(word) {
                a = Term(word);
                b = Term(stack.words.pop().expect("term pair is complete"));
                continue 'term;
            }
            match word >> WORK_OP_SHIFT {
                EQ_ARRAY_OP => {
                    let start = stack.words.pop().expect("array start is present") as usize;
                    let array_index = stack.words.pop().expect("array handle is present") as usize;
                    let (result, len) = {
                        let pair = &stack.arrays[array_index];
                        (
                            first_unequal(&pair.left, &pair.right, start),
                            pair.left.len(),
                        )
                    };
                    let Some((index, next_a, next_b)) = result else {
                        stack.arrays.truncate(array_index);
                        continue 'term;
                    };
                    if both_immed(next_a, next_b) {
                        return false;
                    }
                    let next = index + 1;
                    if next < len {
                        stack.push_array_index(array_index, next);
                    } else {
                        stack.arrays.truncate(array_index);
                    }
                    a = next_a;
                    b = next_b;
                    continue 'term;
                }
                EQ_FLATMAP_VALUES_OP => {
                    let end = stack.words.pop().expect("value count is present") as usize;
                    let start = stack.words.pop().expect("value index is present") as usize;
                    let left_map = Term(stack.words.pop().expect("left map is present"));
                    let right_map = Term(stack.words.pop().expect("right map is present"));
                    let (result, len) =
                        crate::hamt::with_flatmap_arrays(left_map, |_, left_values| {
                            crate::hamt::with_flatmap_arrays(right_map, |_, right_values| {
                                let left = EqArray::Words(&left_values[..end]);
                                let right = EqArray::Words(&right_values[..end]);
                                (first_unequal(&left, &right, start), left.len())
                            })
                            .expect("right map is a live flatmap")
                        })
                        .expect("left map is a live flatmap");
                    let Some((index, next_a, next_b)) = result else {
                        continue 'term;
                    };
                    if both_immed(next_a, next_b) {
                        return false;
                    }
                    let next = index + 1;
                    if next < len {
                        stack.push_flatmap_values(left_map, right_map, next, end);
                    }
                    a = next_a;
                    b = next_b;
                    continue 'term;
                }
                EQ_HASHMAP_OP => {
                    let index = stack
                        .words
                        .pop()
                        .expect("hashmap iterator handle is present")
                        as usize;
                    let (left_pair, right_pair) = {
                        let iterators = &mut stack.hashmaps[index];
                        (iterators.left.next(), iterators.right.next())
                    };
                    match (left_pair, right_pair) {
                        (None, None) => {
                            stack.hashmaps.truncate(index);
                            continue 'term;
                        }
                        (Some((left_key, left_value)), Some((right_key, right_value))) => {
                            stack.push_hashmap_index(index);
                            stack.push_terms(left_value, right_value);
                            stack.push_terms(left_key, right_key);
                            continue 'term;
                        }
                        _ => return false,
                    }
                }
                _ => unreachable!("invalid equality work word"),
            }
        }
        // Port of erts/emulator/beam/utils.c:1125-1190 (eq), OTP-29.1.1.
        let Some(kind) = eq_compound_kind(a, b) else {
            return false;
        };
        match kind {
            TermKind::Number => {
                if !exact_number_eq(a, b) {
                    return false;
                }
            }
            TermKind::Atom => {
                // Port of erts/emulator/beam/utils.c:1728-1737, OTP-29.1.1.
                // Atom identities are canonical in the VM's global atom table.
                if a.as_atom() != b.as_atom() {
                    return false;
                }
            }
            TermKind::Nil => {}
            TermKind::Pid | TermKind::Port => {
                if identity_cmp(a.identity().unwrap(), b.identity().unwrap()) != Ordering::Equal {
                    return false;
                }
            }
            TermKind::Ref => {
                if !exact_ref_eq(a, b) {
                    return false;
                }
            }
            TermKind::List => {
                // Port of erts/emulator/beam/utils.c:1137-1161, OTP-29.1.1.
                // Keep equal list cells in the list walk instead of repeating term-tag dispatch.
                loop {
                    // SAFETY: the caller keeps both list cells live and stable.
                    let (ah, at) = unsafe { a.cons_ref().unwrap() };
                    // SAFETY: the caller keeps both list cells live and stable.
                    let (bh, bt) = unsafe { b.cons_ref().unwrap() };
                    if ah != bh {
                        pending.get_or_insert_with(EqStack::new).push_terms(at, bt);
                        a = ah;
                        b = bh;
                        continue 'term;
                    }
                    if at == bt {
                        break;
                    }
                    if at.0 & 3 != 1 || bt.0 & 3 != 1 {
                        a = at;
                        b = bt;
                        continue 'term;
                    }
                    a = at;
                    b = bt;
                }
            }
            TermKind::Tuple => {
                // SAFETY: both tuple payloads remain live and stable.
                let (av, bv) = unsafe { (a.tuple_ref().unwrap(), b.tuple_ref().unwrap()) };
                if av.len() != bv.len() {
                    return false;
                }
                let left = EqArray::Tuple(av);
                let right = EqArray::Tuple(bv);
                if let Some((index, x, y)) = first_unequal(&left, &right, 0) {
                    if both_immed(x, y) {
                        return false;
                    }
                    let next = index + 1;
                    if next < left.len() {
                        pending
                            .get_or_insert_with(EqStack::new)
                            .push_array(left, right, next);
                    }
                    a = x;
                    b = y;
                    continue 'term;
                }
            }
            TermKind::Bitstring => {
                if bits_cmp(a, b) != Ordering::Equal {
                    return false;
                }
            }
            TermKind::Map => {
                let len = crate::hamt::len(a);
                if len != crate::hamt::len(b) {
                    return false;
                }
                if a.is_hashmap() != b.is_hashmap() {
                    let Some(values) = exact_eq_mixed_map_layouts(a, b) else {
                        return false;
                    };
                    for (left_value, right_value) in values {
                        pending
                            .get_or_insert_with(EqStack::new)
                            .push_terms(left_value, right_value);
                    }
                    a = b;
                    continue 'term;
                }
                if a.is_hashmap() {
                    pending.get_or_insert_with(EqStack::new).push_hashmap(a, b);
                    a = b;
                    continue 'term;
                }
                let left_keys = a.flatmap_keys_tuple().expect("left map is a live flatmap");
                let right_keys = b.flatmap_keys_tuple().expect("right map is a live flatmap");
                if len != 0 {
                    pending
                        .get_or_insert_with(EqStack::new)
                        .push_flatmap_values(a, b, 0, len);
                }
                a = left_keys;
                b = right_keys;
                continue 'term;
            }
            TermKind::Record => {
                // SAFETY: both record definitions and instances remain live.
                let (av, bv) = unsafe { (a.record_ref().unwrap(), b.record_ref().unwrap()) };
                if node_order(av.module(), bv.module()) != Ordering::Equal
                    || node_order(av.name(), bv.name()) != Ordering::Equal
                    || av.is_exported() != bv.is_exported()
                    || av.len() != bv.len()
                {
                    return false;
                }
                for i in 0..av.len() {
                    let (ai, bi) = (av.sorted_index(i).unwrap(), bv.sorted_index(i).unwrap());
                    if node_order(av.key(ai).unwrap(), bv.key(bi).unwrap()) != Ordering::Equal {
                        return false;
                    }
                    pending
                        .get_or_insert_with(EqStack::new)
                        .push_terms(av.value(ai).unwrap(), bv.value(bi).unwrap());
                }
            }
            TermKind::Fun => {
                // SAFETY: both fun entries are retained by their owning heaps.
                let (av, bv) = unsafe { (a.fun_ref().unwrap(), b.fun_ref().unwrap()) };
                match (av, bv) {
                    (
                        FunRef::Local {
                            entry: ae,
                            free_vars: af,
                        },
                        FunRef::Local {
                            entry: be,
                            free_vars: bf,
                        },
                    ) => {
                        if node_order(ae.module, be.module) != Ordering::Equal
                            || ae.index != be.index
                            || ae.old_uniq != be.old_uniq
                            || af.len() != bf.len()
                        {
                            return false;
                        }
                        let left = EqArray::Words(af);
                        let right = EqArray::Words(bf);
                        if let Some((index, x, y)) = first_unequal(&left, &right, 0) {
                            if both_immed(x, y) {
                                return false;
                            }
                            let next = index + 1;
                            if next < left.len() {
                                pending
                                    .get_or_insert_with(EqStack::new)
                                    .push_array(left, right, next);
                            }
                            a = x;
                            b = y;
                            continue 'term;
                        }
                    }
                    (FunRef::Export { entry: ae }, FunRef::Export { entry: be }) => {
                        if node_order(ae.module, be.module) != Ordering::Equal
                            || node_order(ae.function, be.function) != Ordering::Equal
                            || ae.arity != be.arity
                        {
                            return false;
                        }
                    }
                    _ => return false,
                }
            }
            _ => {
                if a.bits() != b.bits() {
                    return false;
                }
            }
        }
        b = a;
    }
}
/// Erlang `==` for implemented types.
pub fn loose_eq(a: Term, b: Term) -> bool {
    cmp_impl(a, b, false) == Ordering::Equal
}

#[cfg(test)]
mod hashmap_oracle_tests {
    use super::{cmp_impl, hashmap_key_hash_order};
    use crate::{Term, TermBuilder, VecHeap};
    use std::cmp::Ordering;
    use std::process::Command;

    fn old_cmp_map_key(left: Term, right: Term) -> Ordering {
        cmp_impl(left, right, true)
    }

    // Test-only copy of the main-branch hashmap loop, retained as a small regression oracle.
    fn old_main_hashmap_cmp(a: Term, b: Term, exact: bool) -> Ordering {
        let mut left = crate::hamt::PairIter::new(a);
        let mut right = crate::hamt::PairIter::new(b);
        let mut ap = left.next();
        let mut bp = right.next();
        let mut min_key = None;
        let mut cmp_res = Ordering::Equal;

        while let (Some((left_key, left_value)), Some((right_key, right_value))) = (ap, bp) {
            let j = old_cmp_map_key(left_key, right_key);
            if j != Ordering::Equal {
                break;
            }
            let is_new_minimum =
                min_key.is_none_or(|current| old_cmp_map_key(left_key, current) == Ordering::Less);
            if is_new_minimum {
                let j = cmp_impl(left_value, right_value, exact);
                if j != Ordering::Equal {
                    min_key = Some(left_key);
                    cmp_res = j;
                }
            }
            ap = left.next();
            bp = right.next();
        }
        if ap.is_none() && bp.is_none() {
            return cmp_res;
        }
        let j = match (ap, bp) {
            (Some((left_key, _)), Some((right_key, _))) => old_cmp_map_key(left_key, right_key),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => unreachable!(),
        };
        let hash_order = hashmap_key_hash_order(ap.map(|pair| pair.0), bp.map(|pair| pair.0));
        let side = if hash_order == Ordering::Equal {
            j
        } else {
            hash_order
        };
        if side == Ordering::Less {
            min_key = Some(ap.unwrap().0);
            cmp_res = Ordering::Less;
            ap = left.next();
        } else {
            min_key = Some(bp.unwrap().0);
            cmp_res = Ordering::Greater;
            bp = right.next();
        }

        loop {
            let j = match (ap, bp) {
                (Some((left_key, _)), Some((right_key, _))) => old_cmp_map_key(left_key, right_key),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => break,
            };
            if j == Ordering::Equal {
                ap = left.next();
                bp = right.next();
                continue;
            }
            let hash_order = hashmap_key_hash_order(ap.map(|pair| pair.0), bp.map(|pair| pair.0));
            let side = if hash_order == Ordering::Equal {
                j
            } else {
                hash_order
            };
            if side == Ordering::Less {
                let key = ap.unwrap().0;
                let j = old_cmp_map_key(key, min_key.unwrap());
                if j == Ordering::Less {
                    min_key = Some(key);
                    cmp_res = Ordering::Less;
                }
                ap = left.next();
            } else {
                let key = bp.unwrap().0;
                let j = old_cmp_map_key(key, min_key.unwrap());
                if j == Ordering::Less {
                    min_key = Some(key);
                    cmp_res = Ordering::Greater;
                }
                bp = right.next();
            }
        }
        cmp_res
    }

    #[test]
    fn minimum_size_mixed_hamt_matches_main_and_erl() {
        let expression = r#"F=fun(I)->case I rem 6 of 0->I+100000; 1->I+0.5; 2->{I}; 3->[I]; 4->binary:copy(<<I:32>>); 5->-I-1 end end, P=[{F((I*37+4*977) rem 5000),I*3-4}||I<-lists:seq(0,30)], M=maps:from_list([{1,17},{1.0,19}]++P), M2=maps:put(1.0,4,M), M3=maps:remove(1.0,maps:put(2.0,4,M)), C=fun(A,B)->if A<B->0; A>B->2; true->1 end end, io:format("~B ~B~n",[C(M,M2),C(M,M3)]),halt()."#;
        let output = Command::new("erl")
            .args(["-noshell", "-eval", expression])
            .output()
            .expect("erl is installed for the differential trace");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        similar_asserts::assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "2 0");

        let mut heap = VecHeap::new();
        let mut builder = TermBuilder::new(&mut heap);
        let float_one = builder.float(1.0).unwrap();
        let mut pairs = vec![
            (Term::small(1).unwrap(), Term::small(17).unwrap()),
            (float_one, Term::small(19).unwrap()),
        ];
        for index in 0..31 {
            let key_index = (index * 37 + 4 * 977) % 5000;
            let n = key_index as i64;
            let key = match key_index % 6 {
                0 => Term::small(n + 100_000).unwrap(),
                1 => builder.float(n as f64 + 0.5).unwrap(),
                2 => builder.tuple(&[Term::small(n).unwrap()]).unwrap(),
                3 => builder.list_from_iter([Term::small(n).unwrap()]).unwrap(),
                4 => builder.binary(&(key_index as u32).to_be_bytes()).unwrap(),
                _ => Term::small(-n - 1).unwrap(),
            };
            pairs.push((key, Term::small(index as i64 * 3 - 4).unwrap()));
        }
        let map = builder.flatmap_from_pairs(&pairs).unwrap();
        let mut value_pairs = pairs.clone();
        value_pairs.push((float_one, Term::small(4).unwrap()));
        let changed_value = builder.flatmap_from_pairs(&value_pairs).unwrap();
        let mut key_pairs = pairs
            .into_iter()
            .filter(|(key, _)| !crate::exact_eq(*key, float_one))
            .collect::<Vec<_>>();
        key_pairs.push((builder.float(2.0).unwrap(), Term::small(4).unwrap()));
        let changed_key = builder.flatmap_from_pairs(&key_pairs).unwrap();
        assert!(map.is_hashmap() && changed_value.is_hashmap() && changed_key.is_hashmap());

        for (right, expected) in [
            (changed_value, Ordering::Greater),
            (changed_key, Ordering::Less),
        ] {
            let old = old_main_hashmap_cmp(map, right, false);
            let new = cmp_impl(map, right, false);
            similar_asserts::assert_eq!(old, expected);
            similar_asserts::assert_eq!(new, expected);
        }
    }
}
