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
            // SAFETY: The header digit count describes initialized magnitude limbs.
            let len = (h >> 6) as usize;
            let mut digits = SmallVec::with_capacity(len);
            for index in 0..len {
                // SAFETY: The header digit count describes initialized magnitude limbs.
                digits.push(unsafe { *p.add(index + 1) });
            }
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
    size_object_inner(
        root,
        false,
        std::collections::HashSet::new(),
        LiteralSkip::None,
        None,
    )
}

/// Words a literal-aware copy needs: literals outside the purge area are not copied.
/// Port of erts/emulator/beam/copy.c:88 (size_object_x with a litopt), OTP-29.1.1.
pub fn size_object_litopt(root: Term, literals: &crate::LiteralAreas) -> usize {
    size_object_inner(
        root,
        false,
        std::collections::HashSet::new(),
        LiteralSkip::Kept(literals),
        None,
    )
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
    let mut stack = Vec::new();
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
    if a == b {
        return Ordering::Equal;
    }
    if let (Some(x), Some(y)) = (a.as_small(), b.as_small()) {
        return x.cmp(&y);
    }
    if let (Some(x), Some(y)) = (a.as_atom(), b.as_atom()) {
        let atoms = global_atoms();
        return atoms.text(x).cmp(&atoms.text(y));
    }
    // Most comparisons inspect only one shallow object. Keep those pending
    // child pairs inline so the common tuple/list ordering path does not
    // allocate once per relational operation.
    let mut pending = SmallVec::<[(Term, Term, bool); 16]>::new();
    pending.push((a, b, exact));
    while let Some((a, b, exact)) = pending.pop() {
        if a == b {
            continue;
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
                let atoms = global_atoms();
                atoms
                    .text(a.as_atom().unwrap())
                    .cmp(&atoms.text(b.as_atom().unwrap()))
            }
            TermKind::Nil => Ordering::Equal,
            TermKind::Pid | TermKind::Port | TermKind::Ref => {
                identity_cmp(a.identity().unwrap(), b.identity().unwrap())
            }
            TermKind::List => {
                // SAFETY: both cells remain on their owning heaps.
                let (ah, at) = unsafe { a.cons_ref().unwrap() };
                // SAFETY: both cells remain on their owning heaps.
                let (bh, bt) = unsafe { b.cons_ref().unwrap() };
                pending.push((at, bt, exact));
                pending.push((ah, bh, exact));
                Ordering::Equal
            }
            TermKind::Tuple => {
                // SAFETY: both tuples remain on their owning heaps.
                let av = unsafe { a.tuple_ref().unwrap() };
                // SAFETY: both tuples remain on their owning heaps.
                let bv = unsafe { b.tuple_ref().unwrap() };
                let c = av.len().cmp(&bv.len());
                if c != Ordering::Equal {
                    return c;
                }
                for i in (0..av.len()).rev() {
                    pending.push((av.get(i).unwrap(), bv.get(i).unwrap(), exact));
                }
                Ordering::Equal
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
                for i in 0..av.len() {
                    let ai = av.original_index(i).unwrap();
                    let bi = bv.original_index(i).unwrap();
                    let c = node_order(av.key(ai).unwrap(), bv.key(bi).unwrap());
                    if c != Ordering::Equal {
                        return c;
                    }
                }
                for i in (0..av.len()).rev() {
                    let ai = av.original_index(i).unwrap();
                    let bi = bv.original_index(i).unwrap();
                    pending.push((av.value(ai).unwrap(), bv.value(bi).unwrap(), exact));
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
                        for i in (0..af.len()).rev() {
                            pending.push((Term(af[i]), Term(bf[i]), exact));
                        }
                        Ordering::Equal
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
                let mut av: SmallVec<[(Term, Term); 32]> = crate::hamt::PairIter::new(a).collect();
                let mut bv: SmallVec<[(Term, Term); 32]> = crate::hamt::PairIter::new(b).collect();
                let c = av.len().cmp(&bv.len());
                if c != Ordering::Equal {
                    return c;
                }
                av.sort_by(|a, b| cmp_impl(a.0, b.0, true));
                bv.sort_by(|a, b| cmp_impl(a.0, b.0, true));
                for i in (0..av.len()).rev() {
                    pending.push((av[i].1, bv[i].1, exact));
                }
                for i in (0..av.len()).rev() {
                    pending.push((av[i].0, bv[i].0, true));
                }
                Ordering::Equal
            }
            _ => a.bits().cmp(&b.bits()),
        };
        if c != Ordering::Equal {
            return c;
        }
    }
    Ordering::Equal
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
    fn fields(term: Term) -> (crate::Atom, u32, [u32; 5], usize) {
        let header = term.header().unwrap();
        // SAFETY: a live reference's header identifies its initialized words.
        let ptr = unsafe { term.raw_ptr() };
        let mut ids = [0; 5];
        let (node, creation, len) = match header & 63 {
            crate::REF => {
                // SAFETY: local reference numbers occupy words one and two.
                unsafe {
                    ids[0] = (*ptr.add(1) >> 32) as u32;
                    ids[1] = *ptr.add(2) as u32;
                    ids[2] = (*ptr.add(2) >> 32) as u32;
                }
                (crate::atoms::NONAME, 0, 3)
            }
            crate::MAGIC_REF => {
                // SAFETY: the magic reference identity occupies word two.
                let id = unsafe { *ptr.add(2) };
                ids[..3].copy_from_slice(&[id as u32, (id >> 32) as u32, u32::MAX]);
                (crate::atoms::NONAME, 0, 3)
            }
            crate::EXTERNAL_REF => {
                // SAFETY: word one retains the Node, followed by packed ids.
                let node = unsafe { &*(*ptr.add(1) as *const crate::Node) };
                let count = if header >> 6 == 4 { 3 } else { 5 };
                for (i, id) in ids.iter_mut().enumerate().take(count) {
                    // SAFETY: count is derived from the external ref header.
                    let word = unsafe { *ptr.add(3 + i / 2) };
                    *id = if i % 2 == 0 {
                        word as u32
                    } else {
                        (word >> 32) as u32
                    };
                }
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
pub fn exact_eq(a: Term, b: Term) -> bool {
    if a == b {
        return true;
    }
    let mut pending: SmallVec<[(Term, Term); 32]> = SmallVec::new();
    pending.push((a, b));
    while let Some((mut a, mut b)) = pending.pop() {
        loop {
            if a == b {
                break;
            }
            let kind = a.classify();
            if kind != b.classify() {
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
                    // SAFETY: the caller keeps both list cells live and stable.
                    let (ah, at) = unsafe { a.cons_ref().unwrap() };
                    // SAFETY: the caller keeps both list cells live and stable.
                    let (bh, bt) = unsafe { b.cons_ref().unwrap() };
                    if ah != bh {
                        pending.push((at, bt));
                        a = ah;
                        b = bh;
                    } else {
                        a = at;
                        b = bt;
                    }
                    continue;
                }
                TermKind::Tuple => {
                    // SAFETY: both tuple payloads remain live and stable.
                    let (av, bv) = unsafe { (a.tuple_ref().unwrap(), b.tuple_ref().unwrap()) };
                    if av.len() != bv.len() {
                        return false;
                    }
                    for i in (0..av.len()).rev() {
                        let (x, y) = (av.get(i).unwrap(), bv.get(i).unwrap());
                        if x != y {
                            pending.push((x, y));
                        }
                    }
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
                        let (ai, bi) =
                            (av.original_index(i).unwrap(), bv.original_index(i).unwrap());
                        if node_order(av.key(ai).unwrap(), bv.key(bi).unwrap()) != Ordering::Equal {
                            return false;
                        }
                        pending.push((av.value(ai).unwrap(), bv.value(bi).unwrap()));
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
                            for i in (0..af.len()).rev() {
                                pending.push((Term(af[i]), Term(bf[i])));
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
            break;
        }
    }
    true
}
/// Erlang `==` for implemented types.
pub fn loose_eq(a: Term, b: Term) -> bool {
    cmp_impl(a, b, false) == Ordering::Equal
}
