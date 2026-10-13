//! OTP's unsalted 64-bit HAMT hash. External node and export pointers are VM-local.
use crate::{FLOAT, NEG_BIG, POS_BIG, Term, TermKind};

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
    fn push(&mut self, term: Term, jobs: &mut Jobs) {
        if term.bits() & 3 == 3 {
            self.alpha(1);
            self.beta(term.bits());
        } else {
            self.alpha(2);
            jobs.push(Job::Visit(term));
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
#[derive(Clone, Copy)]
enum Job {
    Visit(Term),
    CdrMarker,
}

/// Work stack that starts in a local array and spills to the heap only when it grows.
// Port of erts/emulator/beam/global.h (DECLARE_ESTACK, DEF_ESTACK_SIZE), OTP-29.1.1.
struct Jobs {
    local: [Job; 16],
    len: usize,
    overflow: Vec<Job>,
}
impl Jobs {
    fn new(first: Job) -> Self {
        Self {
            local: [first; 16],
            len: 1,
            overflow: Vec::new(),
        }
    }
    #[inline]
    fn push(&mut self, job: Job) {
        if self.overflow.is_empty() && self.len < self.local.len() {
            self.local[self.len] = job;
            self.len += 1;
        } else {
            self.overflow.push(job);
        }
    }
    #[inline]
    fn pop(&mut self) -> Option<Job> {
        if let Some(job) = self.overflow.pop() {
            return Some(job);
        }
        self.len = self.len.checked_sub(1)?;
        Some(self.local[self.len])
    }
}
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
pub fn internal_salted_hash(term: Term, salt: u64) -> u64 {
    if term.bits() & 3 == 3 {
        return mix64(term.bits().wrapping_add(salt));
    }
    let mut state = State {
        alpha: salt,
        beta: salt,
        ticks: 0,
    };
    let mut jobs = Jobs::new(Job::Visit(term));
    while let Some(job) = jobs.pop() {
        match job {
            Job::CdrMarker => state.beta(4),
            Job::Visit(mut term) => match term.classify() {
                TermKind::Nil | TermKind::Atom | TermKind::Catch => {
                    state.alpha(1);
                    state.beta(term.bits());
                }
                TermKind::Number if term.as_small().is_some() => {
                    state.alpha(1);
                    state.beta(term.bits());
                }
                TermKind::Pid if term.as_pid().is_some() => {
                    state.alpha(1);
                    state.beta(term.bits());
                }
                TermKind::Port if term.as_port().is_some() => {
                    state.alpha(1);
                    state.beta(term.bits());
                }
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
                            jobs.push(Job::Visit(tail));
                        } else {
                            jobs.push(Job::Visit(tail));
                            if tail.classify() != TermKind::List {
                                jobs.push(Job::CdrMarker);
                            }
                            state.alpha(3);
                            jobs.push(Job::Visit(head));
                        }
                    } else if term.classify() != TermKind::List {
                        jobs.push(Job::Visit(term));
                    }
                }
                TermKind::Tuple => {
                    // SAFETY: tuple remains live throughout hashing.
                    let tuple = unsafe { term.tuple_ref().unwrap() };
                    state.alpha(6);
                    state.beta(tuple.len() as u64);
                    if !tuple.is_empty() {
                        for i in 0..tuple.len() - 1 {
                            state.push(tuple.get(i).unwrap(), &mut jobs);
                        }
                        // erts walks the last element next (make_internal_hash, `term =
                        // elements[arity]; continue`). An immediate is mixed here, which is the
                        // step the stack pop would take next, so the stack is only for boxed terms.
                        let last = tuple.get(tuple.len() - 1).unwrap();
                        if last.bits() & 3 == 3 {
                            state.alpha(1);
                            state.beta(last.bits());
                        } else {
                            jobs.push(Job::Visit(last));
                        }
                    }
                }
                TermKind::Record => {
                    // SAFETY: record and its definition remain live throughout hashing.
                    let record = unsafe { term.record_ref().unwrap() };
                    state.alpha(7);
                    state.beta((record.len() + 1) as u64);
                    state.push(
                        Term::small(record.definition_hash() as i64).unwrap(),
                        &mut jobs,
                    );
                    if !record.is_empty() {
                        for i in 0..record.len() - 1 {
                            state.push(record.value(i).unwrap(), &mut jobs);
                        }
                        jobs.push(Job::Visit(record.value(record.len() - 1).unwrap()));
                    }
                }
                TermKind::Map if !term.is_hashmap() => {
                    // SAFETY: flatmap keys and values remain live.
                    let map = unsafe { term.flatmap_ref().unwrap() };
                    state.alpha(8);
                    state.beta(map.len() as u64);
                    if !map.is_empty() {
                        for i in 0..map.len() - 1 {
                            let (key, val) = map.iter().nth(i).unwrap();
                            state.push(val, &mut jobs);
                            state.push(key, &mut jobs);
                        }
                        let (key, val) = map.iter().last().unwrap();
                        state.push(val, &mut jobs);
                        jobs.push(Job::Visit(key));
                    }
                }
                TermKind::Map => {
                    // Port of erts/emulator/beam/erl_term_hashing.c:1899-1979
                    // (make_internal_hash map branch), OTP-29.1.1.
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
                            state.push(value, &mut jobs);
                            state.push(key, &mut jobs);
                        } else {
                            jobs.push(Job::Visit(child));
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
                                    state.push(Term(*value), &mut jobs);
                                }
                                jobs.push(Job::Visit(Term(free_vars[free_vars.len() - 1])));
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
                other => panic!("unsupported term kind in internal_hash: {other:?}"),
            },
        }
    }
    state.finish()
}
