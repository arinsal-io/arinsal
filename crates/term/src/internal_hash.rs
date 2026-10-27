//! OTP's unsalted 64-bit HAMT hash. External node and export pointers are VM-local.
use crate::{FLOAT, NEG_BIG, POS_BIG, Term, TermKind};
use smallvec::SmallVec;

const C1: u64 = 0x87c3_7b91_1142_53d5;
const C2: u64 = 0x4cf5_ad43_2745_937f;

// Port of erts/emulator/beam/erl_term_hashing.c:1750 (ihash_mix64), OTP-29.1.1.
#[inline(always)]
fn mix64(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    h ^ (h >> 33)
}
struct State {
    alpha: u64,
    beta: u64,
    ticks: u64,
}
impl State {
    #[inline]
    fn alpha(&mut self, value: u64) {
        let x = value.wrapping_mul(C1).rotate_left(31).wrapping_mul(C2);
        self.alpha ^= x;
        self.alpha = self
            .alpha
            .rotate_left(27)
            .wrapping_add(self.beta)
            .wrapping_mul(5)
            .wrapping_add(0x52dc_e729);
        self.ticks += 1;
    }
    #[inline]
    fn beta(&mut self, value: u64) {
        let x = value.wrapping_mul(C2).rotate_left(33).wrapping_mul(C1);
        self.beta ^= x;
        self.beta = self
            .beta
            .rotate_left(31)
            .wrapping_add(self.alpha)
            .wrapping_mul(5)
            .wrapping_add(0x3849_5ab5);
        self.ticks += 1;
    }
    // Port of IHASH_PUSH_TERM in erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
    #[inline(always)]
    fn push_term(&mut self, term: Term, stack: &mut SmallVec<[u64; 16]>) {
        if term.bits() & 3 == 3 {
            self.alpha(1);
            self.beta(term.bits());
        } else {
            self.alpha(2);
            stack.push(term.bits());
        }
    }
    fn finish(mut self) -> u64 {
        self.alpha ^= self.ticks;
        self.beta ^= self.ticks;
        self.alpha = self.alpha.wrapping_add(self.beta);
        self.beta = self.beta.wrapping_add(self.alpha);
        self.alpha = mix64(self.alpha);
        self.beta = mix64(self.beta);
        self.alpha = self.alpha.wrapping_add(self.beta);
        self.beta = self.beta.wrapping_add(self.alpha);
        self.alpha ^ self.beta
    }
}
// Port of IHASH_CAR_MARKER / IHASH_CDR_MARKER in
// erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1. These tagged header words are not terms.
const IHASH_CAR_MARKER: u64 = (1 << 6) | 0x10;
const IHASH_CDR_MARKER: u64 = (2 << 6) | 0x10;
/// OTP `erts_internal_hash` for terms on this VM's heap.
/// Port of `erts/emulator/beam/erl_term_hashing.c:1770` (`make_internal_hash`), OTP-29.1.1.
#[inline(always)]
pub fn internal_hash(term: Term) -> u64 {
    if term.bits() & 3 == 3 {
        mix64(term.bits())
    } else {
        internal_salted_hash(term, 0)
    }
}
/// `erts_internal_hash` of an immediate term given by its word, as the loader computes
/// for `i_get_map_element_hash` and the JIT's `emit_internal_hash_helper` does inline.
// Port of erts/emulator/beam/erl_term_hashing.c:1770-1776 (make_internal_hash, immediate
// fast path), OTP-29.1.1.
pub fn immediate_internal_hash(word: u64) -> u64 {
    mix64(word)
}
/// OTP internal hash with an explicit salt. OTP's ordinary internal hash uses zero.
// Port of make_internal_hash and erts_internal_salted_hash in
// erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
pub fn internal_salted_hash(term: Term, salt: u64) -> u64 {
    if term.bits() & 3 == 3 {
        return mix64(term.bits().wrapping_add(salt));
    }
    let mut state = State {
        alpha: salt,
        beta: salt,
        ticks: 0,
    };
    let mut stack: SmallVec<[u64; 16]> = SmallVec::new();
    let mut term = term;

    // Port of make_internal_hash's DECLARE_ESTACK loop and pop_next label in
    // erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1. Each stack entry is one Eterm word.
    loop {
        match term.bits() {
            IHASH_CAR_MARKER => {
                state.beta(3);
                term = Term(stack.pop().expect("CAR marker has a pending term"));
                continue;
            }
            IHASH_CDR_MARKER => {
                state.beta(4);
                term = Term(stack.pop().expect("CDR marker has a pending term"));
                continue;
            }
            _ => {}
        }

        if term.bits() & 3 == 3 {
            state.alpha(1);
            state.beta(term.bits());
        } else {
            match term.classify() {
                TermKind::List => {
                    let mut value = 0_u64;
                    let mut bytes = 0_u64;
                    // SAFETY: list cells remain live throughout hashing.
                    while let Some((head, tail)) = unsafe { term.cons_ref() } {
                        if let Some(byte) = head.as_small().filter(|n| (0..=255).contains(n)) {
                            value = (value << 8) | byte as u64;
                            bytes += 1;
                            if bytes == 4 {
                                state.alpha((value << 32) | (5 | (bytes << 8)));
                                value = 0;
                                bytes = 0;
                            }
                            term = tail;
                        } else {
                            break;
                        }
                    }
                    if bytes > 0 {
                        state.alpha((value << 32) | (5 | (bytes << 8)));
                    }
                    // SAFETY: list cells remain live throughout hashing.
                    if let Some((head, tail)) = unsafe { term.cons_ref() } {
                        if head.bits() & 3 == 3 {
                            state.alpha(1 | (3 << 32));
                            state.beta(head.bits());
                            if tail.classify() != TermKind::List {
                                state.alpha(4);
                            }
                            term = tail;
                        } else {
                            stack.push(tail.bits());
                            if tail.classify() != TermKind::List {
                                stack.push(IHASH_CDR_MARKER);
                            }
                            state.alpha(3);
                            term = head;
                        }
                    }
                    continue;
                }
                TermKind::Tuple => {
                    // SAFETY: tuple remains live throughout hashing.
                    let tuple = unsafe { term.tuple_ref().unwrap() };
                    state.alpha(6);
                    state.beta(tuple.len() as u64);
                    if !tuple.is_empty() {
                        for i in 0..tuple.len() - 1 {
                            state.push_term(tuple.get(i).unwrap(), &mut stack);
                        }
                        term = tuple.get(tuple.len() - 1).unwrap();
                        continue;
                    }
                }
                TermKind::Record => {
                    // SAFETY: record and its definition remain live throughout hashing.
                    let record = unsafe { term.record_ref().unwrap() };
                    state.alpha(7);
                    state.beta((record.len() + 1) as u64);
                    state.push_term(
                        Term::small(record.definition_hash() as i64).unwrap(),
                        &mut stack,
                    );
                    if !record.is_empty() {
                        for i in 0..record.len() - 1 {
                            state.push_term(record.value(i).unwrap(), &mut stack);
                        }
                        term = record.value(record.len() - 1).unwrap();
                        continue;
                    }
                }
                TermKind::Map if !term.is_hashmap() => {
                    // SAFETY: flatmap keys and values remain live.
                    let map = unsafe { term.flatmap_ref().unwrap() };
                    state.alpha(8);
                    state.beta(map.len() as u64);
                    if !map.is_empty() {
                        let mut entries = map.iter();
                        for _ in 0..map.len() - 1 {
                            let (key, value) = entries.next().unwrap();
                            state.push_term(value, &mut stack);
                            state.push_term(key, &mut stack);
                        }
                        let (key, value) = entries.next().unwrap();
                        state.push_term(value, &mut stack);
                        term = key;
                        continue;
                    }
                }
                TermKind::Map => {
                    // Port of the map branch in make_internal_hash,
                    // erts/emulator/beam/erl_term_hashing.c:1899-1979, OTP-29.1.1.
                    let header = term.header().unwrap();
                    let kind = (header >> 6) & 3;
                    if kind == 2 || kind == 3 {
                        state.alpha(if kind == 2 { 9 } else { 10 });
                        state.beta(crate::hamt::len(term) as u64);
                    } else {
                        state.alpha(11);
                    }
                    // SAFETY: the live node header describes all child slots.
                    let ptr = unsafe { term.raw_ptr() };
                    // SAFETY: the node is initialized on its owning heap.
                    let words = unsafe { crate::boxed_object_words(header, ptr) };
                    for i in crate::hamt::child_range(header, words) {
                        // SAFETY: i indexes an initialized child term.
                        let child = Term(unsafe { *ptr.add(i) });
                        if child.classify() == TermKind::List {
                            // SAFETY: a HAMT leaf is a two-word cons cell.
                            let (key, value) = unsafe { child.cons_ref().unwrap() };
                            state.push_term(value, &mut stack);
                            state.push_term(key, &mut stack);
                        } else {
                            stack.push(child.bits());
                        }
                    }
                }
                TermKind::Fun => {
                    // SAFETY: owning heap retains the fun entry.
                    match unsafe { term.fun_ref().unwrap() } {
                        crate::FunRef::Local { entry, free_vars } => {
                            state.alpha(13 | ((free_vars.len() as u64) << 32));
                            state.beta(entry.index as u64 | ((entry.old_uniq as u64) << 32));
                            state.alpha(1);
                            state.beta(Term::atom(entry.module).bits());
                            if !free_vars.is_empty() {
                                for value in &free_vars[..free_vars.len() - 1] {
                                    state.push_term(Term(*value), &mut stack);
                                }
                                term = Term(free_vars[free_vars.len() - 1]);
                                continue;
                            }
                        }
                        crate::FunRef::Export { .. } => {
                            // SAFETY: export pointer occupies fun word one.
                            let entry_pointer = unsafe { *term.raw_ptr().add(1) };
                            state.alpha(14);
                            state.beta(entry_pointer);
                        }
                    }
                }
                TermKind::Bitstring => {
                    // SAFETY: backing data remains live throughout hashing.
                    let view = unsafe { term.binary_ref().unwrap() };
                    state.alpha(12);
                    state.beta(view.bit_len() as u64);
                    if view.bit_len() > 0 {
                        let count = view.bit_len().div_ceil(8);
                        let mut shifted = Vec::new();
                        let bytes = if view.start_bit().is_multiple_of(8) {
                            &view.bytes()[view.start_bit() / 8..view.start_bit() / 8 + count]
                        } else {
                            shifted.resize(count, 0);
                            for i in 0..view.bit_len() {
                                let bit = (view.bytes()[(view.start_bit() + i) / 8]
                                    >> (7 - (view.start_bit() + i) % 8))
                                    & 1;
                                shifted[i / 8] |= bit << (7 - i % 8);
                            }
                            &shifted
                        };
                        let whole = view.bit_len() / 8;
                        let mut offset = 0;
                        while offset + 16 <= whole {
                            state.alpha(u64::from_le_bytes(
                                bytes[offset..offset + 8].try_into().unwrap(),
                            ));
                            state.beta(u64::from_le_bytes(
                                bytes[offset + 8..offset + 16].try_into().unwrap(),
                            ));
                            offset += 16;
                        }
                        let remaining = whole - offset;
                        if remaining > 8 {
                            let mut data = [0; 8];
                            data[..remaining - 8]
                                .copy_from_slice(&bytes[offset + 8..offset + remaining]);
                            state.beta ^= u64::from_le_bytes(data)
                                .wrapping_mul(C2)
                                .rotate_left(33)
                                .wrapping_mul(C1);
                        }
                        if remaining > 0 {
                            let mut data = [0; 8];
                            data[..remaining.min(8)]
                                .copy_from_slice(&bytes[offset..offset + remaining.min(8)]);
                            state.alpha ^= u64::from_le_bytes(data)
                                .wrapping_mul(C1)
                                .rotate_left(31)
                                .wrapping_mul(C2);
                        }
                        let tail = view.bit_len() % 8;
                        if tail > 0 {
                            state.alpha((bytes[whole] >> (8 - tail)) as u64);
                        }
                    }
                }
                TermKind::Number => {
                    let h = term.header().unwrap();
                    // SAFETY: numeric boxed header determines payload layout.
                    let p = unsafe { term.raw_ptr() };
                    if h & 63 == FLOAT {
                        // SAFETY: float payload occupies one word.
                        let bits = unsafe { *p.add(1) };
                        state.alpha(21);
                        state.beta(bits);
                    } else if h & 63 == POS_BIG || h & 63 == NEG_BIG {
                        let n = (h >> 6) as usize;
                        state.alpha((if h & 63 == NEG_BIG { 15 } else { 16 }) | ((n as u64) << 32));
                        for i in (0..n).step_by(2) {
                            // SAFETY: bignum header contains n digit words.
                            let digit = unsafe { *p.add(1 + i) };
                            if i + 1 < n {
                                state.alpha(digit);
                                // SAFETY: i+1 is within the digit allocation.
                                state.beta(unsafe { *p.add(2 + i) });
                            } else {
                                state.beta(digit);
                            }
                        }
                    }
                }
                TermKind::Ref => {
                    let identity = term.identity().unwrap();
                    if let crate::Identity::Ref { ids, .. } = identity {
                        if term.header().is_some_and(|h| h & 63 == crate::REF) {
                            state.alpha(17 | ((ids[0] as u64) << 32));
                            state.beta(ids[1] as u64 | ((ids[2] as u64) << 32));
                        } else {
                            state.alpha(18 | ((ids.len() as u64) << 32));
                            for pair in ids.chunks(2) {
                                state.beta(
                                    pair[0] as u64
                                        | ((pair.get(1).copied().unwrap_or(0) as u64) << 32),
                                );
                            }
                            // SAFETY: external node pointer is in word one.
                            state.alpha(unsafe { *term.raw_ptr().add(1) });
                        }
                    }
                }
                TermKind::Pid => {
                    if let crate::Identity::Pid { index, serial, .. } = term.identity().unwrap() {
                        // SAFETY: external pid word one contains its retained node pointer.
                        let node = unsafe { *term.raw_ptr().add(1) };
                        state.alpha(19);
                        state.beta(node);
                        state.alpha(index as u64 | ((serial as u64) << 32));
                    }
                }
                TermKind::Port => {
                    if let crate::Identity::Port { id, .. } = term.identity().unwrap() {
                        // SAFETY: external port word one contains its retained node pointer.
                        let node = unsafe { *term.raw_ptr().add(1) };
                        state.alpha(20);
                        state.beta(node);
                        state.alpha(id);
                    }
                }
                TermKind::Nil | TermKind::Atom | TermKind::Catch => {
                    unreachable!("immediate terms are handled before classification")
                }
                other => panic!("unsupported term kind in internal_hash: {other:?}"),
            }
        }

        match stack.pop() {
            Some(word) => term = Term(word),
            None => return state.finish(),
        }
    }
}
