//! Iterative comparison and object sizing.
use crate::FunRef;
use crate::identity::node_order;
use crate::{EMPTY_TUPLE, FLOAT, Identity, NEG_BIG, POS_BIG, Term, TermKind, global_atoms};
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
pub fn cmp(a: Term, b: Term) -> Ordering {
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
    if a == b {
        return Ordering::Equal;
    }
    if let (Some(x), Some(y)) = (a.as_small(), b.as_small()) {
        return x.cmp(&y);
    }
    if let (Some(x), Some(y)) = (a.as_atom(), b.as_atom()) {
        return global_atoms().cmp_atoms(x, y);
    }
    let mut pending = SmallVec::<[CmpWork<'_>; 16]>::new();
    pending.push(CmpWork::Terms {
        left: a,
        right: b,
        exact,
    });
    while let Some(work) = pending.pop() {
        let (mut a, mut b, exact) = match work {
            CmpWork::Terms { left, right, exact } => (left, right, exact),
            CmpWork::Array {
                left,
                right,
                start,
                exact,
            } => match first_cmp_unequal(&left, &right, start) {
                Err(order) => return order,
                Ok(None) => continue,
                Ok(Some((index, left_term, right_term))) => {
                    let next = index + 1;
                    if next < left.len() {
                        pending.push(CmpWork::Array {
                            left,
                            right,
                            start: next,
                            exact,
                        });
                    }
                    (left_term, right_term, exact)
                }
            },
            CmpWork::FlatmapValues {
                left_map,
                right_map,
                start,
                end,
                exact,
            } => {
                match first_cmp_flatmap_values(left_map, right_map, start, end, exact, &mut pending)
                {
                    Err(order) => return order,
                    Ok(None) => continue,
                    Ok(Some((left_term, right_term))) => (left_term, right_term, exact),
                }
            }
            CmpWork::FlatmapAtomValues {
                left_map,
                right_map,
                start,
                remaining,
                exact,
            } => {
                let order = crate::hamt::with_flatmap_arrays(left_map, |left_keys, left_values| {
                    crate::hamt::with_flatmap_arrays(right_map, |_, right_values| {
                        cmp_flatmap_atom_values(
                            left_keys,
                            left_values,
                            right_values,
                            start,
                            remaining,
                            exact,
                        )
                    })
                    .expect("right map is a live flatmap")
                })
                .expect("left map is a live flatmap");
                if order != Ordering::Equal {
                    return order;
                }
                continue;
            }
        };
        loop {
            if a == b {
                break;
            }
            // Port of the immediate fast paths in erts/emulator/beam/utils.c:1723-1739,
            // OTP-29.1.1. They also apply after a list or nested compound advances its pair.
            if let (Some(left), Some(right)) = (a.as_atom(), b.as_atom()) {
                return global_atoms().cmp_atoms(left, right);
            }
            if let (Some(left), Some(right)) = (a.as_small(), b.as_small()) {
                return left.cmp(&right);
            }
            // Port of the primary-list dispatch in erts/emulator/beam/utils.c:1827-1850,
            // OTP-29.1.1. Common list pairs stay in the tail-recursive path without classifying
            // both terms on every cons cell.
            if a.bits() & 3 == 1 {
                if b.bits() & 3 != 1 {
                    return TermKind::List.cmp(&b.classify());
                }
                // SAFETY: both list cells remain live on their owning heaps for this comparison.
                let (left_head, left_tail) = unsafe { a.cons_ref().unwrap() };
                // SAFETY: both list cells remain live on their owning heaps for this comparison.
                let (right_head, right_tail) = unsafe { b.cons_ref().unwrap() };
                if left_head != right_head {
                    pending.push(CmpWork::Terms {
                        left: left_tail,
                        right: right_tail,
                        exact,
                    });
                    a = left_head;
                    b = right_head;
                } else {
                    a = left_tail;
                    b = right_tail;
                }
                continue;
            }
            if b.bits() & 3 == 1 {
                return a.classify().cmp(&TermKind::List);
            }
            let ak = a.classify();
            let bk = b.classify();
            let c = ak.cmp(&bk);
            if c != Ordering::Equal {
                return c;
            }
            let c = match ak {
                TermKind::Number => number_cmp(a, b, exact),
                TermKind::Atom => {
                    global_atoms().cmp_atoms(a.as_atom().unwrap(), b.as_atom().unwrap())
                }
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
                        return c;
                    }
                    let left = CmpArray::Tuple(av);
                    let right = CmpArray::Tuple(bv);
                    match first_cmp_unequal(&left, &right, 0) {
                        Err(order) => return order,
                        Ok(None) => break,
                        Ok(Some((index, left_term, right_term))) => {
                            let next = index + 1;
                            if next < left.len() {
                                pending.push(CmpWork::Array {
                                    left,
                                    right,
                                    start: next,
                                    exact,
                                });
                            }
                            a = left_term;
                            b = right_term;
                            continue;
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
                        return c;
                    }
                    // Port of erts/emulator/beam/erl_record.c:696-769, OTP-29.1.1.
                    for i in 0..av.len() {
                        let ai = av.sorted_index(i).unwrap();
                        let bi = bv.sorted_index(i).unwrap();
                        let c = node_order(av.key(ai).unwrap(), bv.key(bi).unwrap());
                        if c != Ordering::Equal {
                            return c;
                        }
                    }
                    for i in (0..av.len()).rev() {
                        let ai = av.sorted_index(i).unwrap();
                        let bi = bv.sorted_index(i).unwrap();
                        pending.push(CmpWork::Terms {
                            left: av.value(ai).unwrap(),
                            right: bv.value(bi).unwrap(),
                            exact,
                        });
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
                                return c;
                            }
                            let left = CmpArray::Words(af);
                            let right = CmpArray::Words(bf);
                            match first_cmp_unequal(&left, &right, 0) {
                                Err(order) => return order,
                                Ok(None) => break,
                                Ok(Some((index, left_term, right_term))) => {
                                    let next = index + 1;
                                    if next < left.len() {
                                        pending.push(CmpWork::Array {
                                            left,
                                            right,
                                            start: next,
                                            exact,
                                        });
                                    }
                                    a = left_term;
                                    b = right_term;
                                    continue;
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
                TermKind::Map => {
                    let c = crate::hamt::len(a).cmp(&crate::hamt::len(b));
                    if c != Ordering::Equal {
                        return c;
                    }
                    if !a.is_hashmap() && !b.is_hashmap() {
                        cmp_flatmap(a, b, exact, &mut pending)
                    } else {
                        cmp_hashmap(a, b, exact)
                    }
                }
                _ => a.bits().cmp(&b.bits()),
            };
            if c != Ordering::Equal {
                return c;
            }
            break;
        }
    }
    Ordering::Equal
}

enum CmpArray<'a> {
    Tuple(crate::TupleRef<'a>),
    Words(&'a [u64]),
}

impl CmpArray<'_> {
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

enum CmpWork<'a> {
    Terms {
        left: Term,
        right: Term,
        exact: bool,
    },
    Array {
        left: CmpArray<'a>,
        right: CmpArray<'a>,
        start: usize,
        exact: bool,
    },
    FlatmapValues {
        left_map: Term,
        right_map: Term,
        start: usize,
        end: usize,
        exact: bool,
    },
    FlatmapAtomValues {
        left_map: Term,
        right_map: Term,
        start: usize,
        remaining: usize,
        exact: bool,
    },
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
fn first_cmp_flatmap_values<'a>(
    left_map: Term,
    right_map: Term,
    start: usize,
    end: usize,
    exact: bool,
    pending: &mut SmallVec<[CmpWork<'a>; 16]>,
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
        pending.push(CmpWork::FlatmapValues {
            left_map,
            right_map,
            start: next,
            end,
            exact,
        });
    }
    Ok(Some((left_term, right_term)))
}

// Port of erts/emulator/beam/utils.c:2030-2104 (flatmap branch of erts_cmp_compound),
// OTP-29.1.1.
fn cmp_flatmap<'a>(
    a: Term,
    b: Term,
    exact: bool,
    pending: &mut SmallVec<[CmpWork<'a>; 16]>,
) -> Ordering {
    crate::hamt::with_flatmap_arrays(a, |left_keys, _| {
        crate::hamt::with_flatmap_arrays(b, |right_keys, _| {
            cmp_flatmap_arrays(a, b, left_keys, right_keys, exact, pending)
        })
        .expect("right map is a live flatmap")
    })
    .expect("left map is a live flatmap")
}

// Port of the flatmap key/value partition phases in erts_cmp_compound,
// erts/emulator/beam/utils.c:1989-2053, OTP-29.1.1.
fn cmp_flatmap_arrays<'a>(
    a: Term,
    b: Term,
    left_keys: &[u64],
    right_keys: &[u64],
    exact: bool,
    pending: &mut SmallVec<[CmpWork<'a>; 16]>,
) -> Ordering {
    let len = crate::hamt::len(a);
    if exact {
        for index in 0..len {
            let order = cmp_map_key(Term(left_keys[index]), Term(right_keys[index]));
            if order != Ordering::Equal {
                return order;
            }
        }
        if len != 0 {
            pending.push(CmpWork::FlatmapValues {
                left_map: a,
                right_map: b,
                start: 0,
                end: len,
                exact,
            });
        }
        return Ordering::Equal;
    }

    let mut split = 0;
    while split < len
        && !(Term(left_keys[split]).as_atom().is_some()
            && Term(right_keys[split]).as_atom().is_some())
    {
        let order = cmp_map_key(Term(left_keys[split]), Term(right_keys[split]));
        if order != Ordering::Equal {
            return order;
        }
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
    let order = flatmap_atom_key_cmp(left_keys, right_keys, number_end, atom_count);
    if order != Ordering::Equal {
        return order;
    }
    for index in atom_end..len {
        let order = cmp_map_key(Term(left_keys[index]), Term(right_keys[index]));
        if order != Ordering::Equal {
            return order;
        }
    }
    if atom_end < len {
        pending.push(CmpWork::FlatmapValues {
            left_map: a,
            right_map: b,
            start: atom_end,
            end: len,
            exact,
        });
    }
    if atom_count != 0 {
        pending.push(CmpWork::FlatmapAtomValues {
            left_map: a,
            right_map: b,
            start: number_end,
            remaining: atom_count,
            exact,
        });
    }
    if number_end != 0 {
        pending.push(CmpWork::FlatmapValues {
            left_map: a,
            right_map: b,
            start: 0,
            end: number_end,
            exact,
        });
    }
    Ordering::Equal
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

// Port of erts/emulator/beam/utils.c:2672-2717 (FLATMAP_ATOM_VALUES), OTP-29.1.1.
fn cmp_flatmap_atom_values(
    left_keys: &[u64],
    left_values: &[u64],
    right_values: &[u64],
    start: usize,
    count: usize,
    exact: bool,
) -> Ordering {
    let mut minimum: Option<(crate::Atom, Ordering)> = None;
    for index in start..start + count {
        let atom = Term(left_keys[index])
            .as_atom()
            .expect("atom partition contains atoms");
        if minimum
            .is_none_or(|(current, _)| global_atoms().cmp_atoms(atom, current) == Ordering::Less)
        {
            let order = cmp_impl(Term(left_values[index]), Term(right_values[index]), exact);
            if order != Ordering::Equal {
                minimum = Some((atom, order));
            }
        }
    }
    minimum.map_or(Ordering::Equal, |(_, order)| order)
}

// Port of erts/emulator/beam/utils.c:2468-2486 (TERM_ARRAY_OP), OTP-29.1.1.
#[inline(always)]
fn cmp_map_key(left: Term, right: Term) -> Ordering {
    if left == right {
        return Ordering::Equal;
    }
    if let (Some(left), Some(right)) = (left.as_small(), right.as_small()) {
        return left.cmp(&right);
    }
    if let (Some(left), Some(right)) = (left.as_atom(), right.as_atom()) {
        return global_atoms().cmp_atoms(left, right);
    }
    cmp_impl(left, right, true)
}

// Port of erts/emulator/beam/utils.c:2511-2665 (hashmap comparison phases), OTP-29.1.1.
fn cmp_hashmap(a: Term, b: Term, exact: bool) -> Ordering {
    let mut left = crate::hamt::PairIter::new(a);
    let mut right = crate::hamt::PairIter::new(b);
    let mut left_pair = left.next();
    let mut right_pair = right.next();
    let mut minimum: Option<(Term, Ordering)> = None;

    while let (Some((left_key, left_value)), Some((right_key, right_value))) =
        (left_pair, right_pair)
    {
        if cmp_map_key(left_key, right_key) != Ordering::Equal {
            break;
        }
        let is_new_minimum =
            minimum.is_none_or(|(current, _)| cmp_map_key(left_key, current) == Ordering::Less);
        if is_new_minimum {
            let value_order = cmp_impl(left_value, right_value, exact);
            if value_order != Ordering::Equal {
                minimum = Some((left_key, value_order));
            }
        }
        left_pair = left.next();
        right_pair = right.next();
    }

    if left_pair.is_none() && right_pair.is_none() {
        return minimum.map_or(Ordering::Equal, |(_, order)| order);
    }

    let key_order = match (left_pair, right_pair) {
        (Some((left_key, _)), Some((right_key, _))) => cmp_map_key(left_key, right_key),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => unreachable!(),
    };
    let hash_order =
        hashmap_key_hash_order(left_pair.map(|pair| pair.0), right_pair.map(|pair| pair.0));
    let first_order = if hash_order == Ordering::Equal {
        key_order
    } else {
        hash_order
    };
    if first_order == Ordering::Less {
        minimum = Some((left_pair.unwrap().0, Ordering::Less));
        left_pair = left.next();
    } else {
        minimum = Some((right_pair.unwrap().0, Ordering::Greater));
        right_pair = right.next();
    }

    loop {
        let current_order = match (left_pair, right_pair) {
            (Some((left_key, _)), Some((right_key, _))) => {
                let order = cmp_map_key(left_key, right_key);
                if order == Ordering::Equal {
                    left_pair = left.next();
                    right_pair = right.next();
                    continue;
                }
                order
            }
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => break,
        };
        let hash_order =
            hashmap_key_hash_order(left_pair.map(|pair| pair.0), right_pair.map(|pair| pair.0));
        let side = if hash_order == Ordering::Equal {
            current_order
        } else {
            hash_order
        };
        if side == Ordering::Less {
            let candidate = left_pair.unwrap().0;
            if cmp_map_key(candidate, minimum.unwrap().0) == Ordering::Less {
                minimum = Some((candidate, Ordering::Less));
            }
            left_pair = left.next();
        } else {
            let candidate = right_pair.unwrap().0;
            if cmp_map_key(candidate, minimum.unwrap().0) == Ordering::Less {
                minimum = Some((candidate, Ordering::Greater));
            }
            right_pair = right.next();
        }
    }
    minimum.map_or(Ordering::Equal, |(_, order)| order)
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
fn exact_map_eq(a: Term, b: Term) -> bool {
    if crate::hamt::len(a) != crate::hamt::len(b) {
        return false;
    }
    if !a.is_hashmap() && !b.is_hashmap() {
        // SAFETY: equal-length flatmaps have initialized key/value arrays.
        unsafe {
            let (ap, bp) = (a.raw_ptr(), b.raw_ptr());
            let (ak, bk) = (Term(*ap.add(2)), Term(*bp.add(2)));
            let len = crate::hamt::len(a);
            let (akp, bkp) = (ak.raw_ptr(), bk.raw_ptr());
            let mut same_keys = true;
            for i in 0..len {
                if !exact_eq(Term(*akp.add(i + 1)), Term(*bkp.add(i + 1))) {
                    same_keys = false;
                    break;
                }
            }
            if same_keys {
                return (0..len).all(|i| exact_eq(Term(*ap.add(i + 3)), Term(*bp.add(i + 3))));
            }
        }
    }
    if a.is_hashmap() && b.is_hashmap() {
        // A canonical HAMT has the same bitmap at every node when keys are
        // unchanged. Walk corresponding slots with an inline depth stack.
        let mut frames: SmallVec<[(Term, Term, usize, usize); 20]> = SmallVec::new();
        let mut nodes = Some((a, b));
        let mut same_shape = true;
        while let Some((left, right)) = nodes.take().or_else(|| {
            while let Some((parent_a, parent_b, next, end)) = frames.last_mut() {
                if *next == *end {
                    frames.pop();
                    continue;
                }
                // SAFETY: both parent ranges contain initialized child slots.
                let child = unsafe {
                    let pair = (
                        Term(*parent_a.raw_ptr().add(*next)),
                        Term(*parent_b.raw_ptr().add(*next)),
                    );
                    *next += 1;
                    pair
                };
                return Some(child);
            }
            None
        }) {
            if left.classify() == TermKind::List && right.classify() == TermKind::List {
                // SAFETY: corresponding HAMT leaves contain key and value.
                let (lk, lv) = unsafe { left.cons_ref().unwrap() };
                // SAFETY: corresponding HAMT leaves contain key and value.
                let (rk, rv) = unsafe { right.cons_ref().unwrap() };
                if lk != rk && !exact_eq(lk, rk) {
                    same_shape = false;
                    break;
                }
                if lv != rv && !exact_eq(lv, rv) {
                    return false;
                }
                continue;
            }
            let (lh, rh) = (left.header(), right.header());
            if lh != rh {
                same_shape = false;
                break;
            }
            let header = lh.unwrap();
            // SAFETY: equal headers describe the same child range in both nodes.
            let words = unsafe { crate::boxed_object_words(header, left.raw_ptr()) };
            let start = if header & 63 == crate::MAP {
                crate::hamt::child_range(header, words).start
            } else {
                1
            };
            frames.push((left, right, start, words));
        }
        if same_shape {
            return true;
        }
    }
    // Collision buckets can have a different stored order; match those maps
    // by exact keys without materializing or sorting the entry arrays.
    for (key, value) in crate::hamt::PairIter::new(a) {
        let mut found = false;
        for (other_key, other_value) in crate::hamt::PairIter::new(b) {
            if exact_eq(key, other_key) {
                if !exact_eq(value, other_value) {
                    return false;
                }
                found = true;
                break;
            }
        }
        if !found {
            return false;
        }
    }
    true
}
/// Erlang `=:=` for implemented types. Signed zero compares by bit pattern.
#[inline]
pub fn exact_eq(a: Term, b: Term) -> bool {
    // Port of erts/emulator/beam/erl_utils.h:113 (EQ), OTP-29.1.1.
    a == b || (!Term(a.0 & b.0).is_immed() && eq(a, b))
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

enum EqWork<'a> {
    Terms(Term, Term),
    Array {
        left: EqArray<'a>,
        right: EqArray<'a>,
        start: usize,
    },
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

/// Port of erts/emulator/beam/utils.c:1125 (eq), OTP-29.1.1.
#[inline(never)]
fn eq(a: Term, b: Term) -> bool {
    let mut pending: SmallVec<[EqWork<'_>; 16]> = SmallVec::new();
    pending.push(EqWork::Terms(a, b));
    while let Some(work) = pending.pop() {
        let (mut a, mut b) = match work {
            EqWork::Terms(a, b) => (a, b),
            EqWork::Array { left, right, start } => {
                let Some((index, a, b)) = first_unequal(&left, &right, start) else {
                    continue;
                };
                let next = index + 1;
                if next < left.len() {
                    pending.push(EqWork::Array {
                        left,
                        right,
                        start: next,
                    });
                }
                (a, b)
            }
        };
        'term: loop {
            if a == b {
                break;
            }
            // Port of erts/emulator/beam/utils.c:1125 (eq): after the raw-word check,
            // only list and boxed primary tags have a structural equality case.
            if a.is_immed() {
                return false;
            }
            let kind = if a.0 & 3 == 1 {
                TermKind::List
            } else {
                a.classify()
            };
            if (kind == TermKind::List && b.0 & 3 != 1)
                || (kind != TermKind::List && kind != b.classify())
            {
                return false;
            }
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
                    if identity_cmp(a.identity().unwrap(), b.identity().unwrap()) != Ordering::Equal
                    {
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
                            pending.push(EqWork::Terms(at, bt));
                            a = ah;
                            b = bh;
                            continue 'term;
                        }
                        if at == bt {
                            break 'term;
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
                    let Some((index, x, y)) = first_unequal(&left, &right, 0) else {
                        break;
                    };
                    let next = index + 1;
                    if next < left.len() {
                        pending.push(EqWork::Array {
                            left,
                            right,
                            start: next,
                        });
                    }
                    a = x;
                    b = y;
                    continue;
                }
                TermKind::Bitstring => {
                    if bits_cmp(a, b) != Ordering::Equal {
                        return false;
                    }
                }
                TermKind::Map => {
                    if !exact_map_eq(a, b) {
                        return false;
                    }
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
                        pending.push(EqWork::Terms(av.value(ai).unwrap(), bv.value(bi).unwrap()));
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
                            let Some((index, x, y)) = first_unequal(&left, &right, 0) else {
                                break;
                            };
                            let next = index + 1;
                            if next < left.len() {
                                pending.push(EqWork::Array {
                                    left,
                                    right,
                                    start: next,
                                });
                            }
                            a = x;
                            b = y;
                            continue;
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
            break;
        }
    }
    true
}
/// Erlang `==` for implemented types.
pub fn loose_eq(a: Term, b: Term) -> bool {
    cmp_impl(a, b, false) == Ordering::Equal
}
