//! Stable external `phash2` hashing for implemented term kinds.
use crate::{
    ARITY, BIN_REF, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, FLOAT, FUN, HEAP_BITS, MAP, NEG_BIG,
    POS_BIG, RECORD, REF, SUB_BITS, Term, TermKind, global_atoms,
};
const H: u32 = 0x9e37_79b9;
type BinaryResume = (usize, (u32, u32, u32), Option<Vec<u8>>);

// Port of erts/emulator/beam/erl_term_hashing.c:426 (MIX), OTP-29.1.1.
#[inline(always)]
fn mix(mut a: u32, mut b: u32, mut c: u32) -> u32 {
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 13);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 8);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 13);
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 12);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 16);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 5);
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 3);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 10);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 15);
    c
}
#[inline(always)]
fn combine(hash: &mut u32, a: u32, b: u32, constant: u32) {
    *hash = mix(constant.wrapping_add(a), constant.wrapping_add(b), *hash);
}
fn atom_hash(text: &str) -> u32 {
    crate::atom::otp_atom_hash(text)
}
fn block_hash(bytes: &[u8], initial: u32) -> u32 {
    // Port of erts/emulator/beam/erl_term_hashing.c:454-515, OTP-29.1.1.
    let mut a = H;
    let mut b = H;
    let mut c = initial;
    let (chunks, remaining) = bytes.as_chunks::<12>();
    for block in chunks {
        a = a.wrapping_add(u32::from_le_bytes(block[0..4].try_into().unwrap()));
        b = b.wrapping_add(u32::from_le_bytes(block[4..8].try_into().unwrap()));
        c = c.wrapping_add(u32::from_le_bytes(block[8..12].try_into().unwrap()));
        let result = mix_state(a, b, c);
        (a, b, c) = result;
    }
    c = c.wrapping_add(bytes.len() as u32);
    for (i, byte) in remaining.iter().enumerate() {
        match i {
            0..=3 => a = a.wrapping_add((*byte as u32) << (8 * i)),
            4..=7 => b = b.wrapping_add((*byte as u32) << (8 * (i - 4))),
            // Jenkins reserves the low byte of `c` for the total length.
            _ => c = c.wrapping_add((*byte as u32) << (8 * (i - 7))),
        }
    }
    mix(a, b, c)
}
fn mix_state(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 13);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 8);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 13);
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 12);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 16);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 5);
    a = a.wrapping_sub(b).wrapping_sub(c) ^ (c >> 3);
    b = b.wrapping_sub(c).wrapping_sub(a) ^ (a << 10);
    c = c.wrapping_sub(a).wrapping_sub(b) ^ (b >> 15);
    (a, b, c)
}

const HASH_MAP_TAIL: Term = Term(1 << 6);
const HASH_MAP_PAIR: Term = Term(2 << 6);

/// Select the same primary-tag arm as `make_hash2_helper` before reading a boxed header.
// Port of erts/emulator/beam/erl_term_hashing.c:1030 (make_hash2_helper), OTP-29.1.1.
#[inline(always)]
fn primary_kind(term: Term) -> TermKind {
    let word = term.word();
    match word & 3 {
        1 => TermKind::List,
        2 => match term.header().unwrap() & 63 {
            ARITY => TermKind::Tuple,
            POS_BIG | NEG_BIG | FLOAT => TermKind::Number,
            REF | EXTERNAL_REF => TermKind::Ref,
            EXTERNAL_PID => TermKind::Pid,
            EXTERNAL_PORT => TermKind::Port,
            FUN => TermKind::Fun,
            RECORD => TermKind::Record,
            MAP => TermKind::Map,
            BIN_REF | HEAP_BITS | SUB_BITS => TermKind::Bitstring,
            _ => TermKind::Invalid,
        },
        3 if word & 15 == 15 => TermKind::Number,
        3 if word & 63 == 0x0b => TermKind::Atom,
        3 if word & 63 == 0x3b => TermKind::Nil,
        3 if word & 15 == 3 => TermKind::Pid,
        3 if word & 15 == 7 => TermKind::Port,
        3 => TermKind::Invalid,
        _ => TermKind::Invalid,
    }
}

enum Hash2Resume {
    /// A byte run in a list that trapped part way.
    ListRun { tail: Term, packed: u32, count: u8 },
    /// A binary hashed in several slices.
    Binary(BinaryJob),
    /// Remaining words in a tuple, record, or local function environment.
    Fields {
        parent: Term,
        kind: FieldKind,
        next: usize,
    },
    /// Remaining digits in a bignum.
    Big { term: Term, next: usize },
    /// Remaining flatmap pairs after a trap in its array loop.
    FlatMap { term: Term, next: usize },
    /// Remaining direct children after a trap in a HAMT node loop.
    MapChildren {
        term: Term,
        children: Box<crate::hamt::HashNodeChildren>,
    },
    /// Map pair setup completed immediately before the helper trapped.
    Common,
}

#[derive(Clone, Copy)]
enum FieldKind {
    Tuple,
    Record,
    Fun,
}

enum FieldProgress {
    Common,
    Compound(Term),
    Yield(usize),
}

/// The saved state of a binary hashed in several slices.
struct BinaryJob {
    term: Term,
    processed: usize,
    state: (u32, u32, u32),
    buffer: Option<Vec<u8>>,
}

/// Bytes of a binary hashed per iteration.
// Port of `BLOCK_HASH_BYTES_PER_ITER` in erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
const BLOCK_HASH_BYTES_PER_ITER: usize = 12;

/// Bytes copied while trapping on a bit-offset binary.
// Port of `BINARY_BUF_SIZE` in erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
const BINARY_BUFFER_SIZE: usize = BLOCK_HASH_BYTES_PER_ITER * 256;

/// Iterations `phash2` runs per reduction left.
// Port of `ITERATIONS_PER_RED` in `make_hash2_helper`, erts/emulator/beam/erl_term_hashing.c,
// OTP-29.1.1.
pub const HASH2_ITERATIONS_PER_RED: i64 = 64;

/// Progress of a resumable `make_hash2`.
pub enum Hash2Progress {
    /// The hash, and the iterations the run consumed.
    Done { hash: u32, used: i64 },
    /// The iteration budget ran out; call [`Hash2Run::run`] again.
    Yield,
}

/// A `make_hash2` that can stop when its iteration budget runs out and continue later.
///
/// Port of the trapping `make_hash2_helper` (`trapping_make_hash2`) in
/// erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1: the work stack is the saved state and
/// every loop iteration, and the inner loops over tuple, record, fun and bignum parts, count as
/// one iteration.
pub struct Hash2Run {
    hash: u32,
    term: Term,
    stack: smallvec::SmallVec<[Term; 16]>,
    hash_xor_pairs: u32,
    resume: Option<Hash2Resume>,
    simple: Option<u32>,
}

struct Hash2Walk<'a> {
    stack: &'a mut smallvec::SmallVec<[Term; 16]>,
    left: &'a mut i64,
    can_trap: bool,
}

fn small_hash(n: i64) -> u32 {
    let mut hash = 0;
    if (-(1 << 27)..(1 << 27)).contains(&n) {
        let signed = n as i32;
        if signed < 0 {
            combine(&mut hash, signed.wrapping_neg() as u32, 0, H);
        }
        combine(&mut hash, signed as u32, 0, H);
    } else {
        let mag = n.unsigned_abs();
        combine(
            &mut hash,
            mag as u32,
            (mag >> 32) as u32,
            H.wrapping_mul(if n < 0 { 10 } else { 11 }),
        );
    }
    hash
}

/// `make_hash2` of an atom or small integer, the cases erts handles before creating its ESTACK.
// Port of erts/emulator/beam/erl_term_hashing.c (make_hash2_helper, the immediate cases),
// OTP-29.1.1.
pub fn hash2_immediate(term: Term) -> Option<u32> {
    simple_hash(term)
}

#[inline]
fn simple_hash(term: Term) -> Option<u32> {
    if term.word() & 3 != 3 {
        return None;
    }
    if let Some(n) = term.as_small() {
        return Some(small_hash(n));
    }
    if let Some(atom) = term.as_atom() {
        return Some(global_atoms().hash(atom).unwrap());
    }
    None
}

fn aligned_binary<'a>(
    view: &'a crate::BinaryRef<'_>,
    size: usize,
    bitsize: usize,
    scratch: &'a mut Vec<u8>,
) -> &'a [u8] {
    let needed = size + usize::from(bitsize != 0);
    if view.start_bit().is_multiple_of(8) {
        let start = view.start_bit() / 8;
        &view.bytes()[start..start + needed]
    } else {
        scratch.resize(needed, 0);
        copy_bit_range(view.bytes(), view.start_bit(), scratch, size * 8 + bitsize);
        scratch
    }
}

/// Copies a forward bit range to a zero-offset buffer, matching `erts_copy_bits_fwd`.
// Port of erts_copy_bits_fwd used by make_hash2_helper, OTP-29.1.1.
fn copy_bit_range(source: &[u8], start_bit: usize, destination: &mut [u8], bit_len: usize) {
    destination.fill(0);
    let source_byte = start_bit / 8;
    let bit_offset = start_bit % 8;
    let whole_bytes = bit_len / 8;
    if bit_offset == 0 {
        destination[..whole_bytes].copy_from_slice(&source[source_byte..source_byte + whole_bytes]);
    } else {
        for (index, byte) in destination[..whole_bytes].iter_mut().enumerate() {
            let current = source[source_byte + index];
            let next = source.get(source_byte + index + 1).copied().unwrap_or(0);
            *byte = (current << bit_offset) | (next >> (8 - bit_offset));
        }
    }
    let tail_bits = bit_len % 8;
    if tail_bits > 0 {
        let bit = start_bit + whole_bytes * 8;
        let first = source[bit / 8];
        let value = if bit.is_multiple_of(8) {
            first
        } else {
            let next = source.get(bit / 8 + 1).copied().unwrap_or(0);
            (first << (bit % 8)) | (next >> (8 - bit % 8))
        };
        destination[whole_bytes] = value & (u8::MAX << (8 - tail_bits));
    }
}

// Port of `block_hash_buffer` in erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
fn block_hash_buffer(state: &mut (u32, u32, u32), bytes: &[u8]) {
    let (mut a, mut b, mut c) = *state;
    for block in bytes.as_chunks::<BLOCK_HASH_BYTES_PER_ITER>().0 {
        a = a.wrapping_add(u32::from_le_bytes(block[0..4].try_into().unwrap()));
        b = b.wrapping_add(u32::from_le_bytes(block[4..8].try_into().unwrap()));
        c = c.wrapping_add(u32::from_le_bytes(block[8..12].try_into().unwrap()));
        (a, b, c) = mix_state(a, b, c);
    }
    *state = (a, b, c);
}

// Port of `block_hash_final_bytes` in erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
fn block_hash_final_bytes(state: (u32, u32, u32), remaining: &[u8], full_length: usize) -> u32 {
    let (mut a, mut b, mut c) = state;
    c = c.wrapping_add(full_length as u32);
    for (i, byte) in remaining.iter().enumerate() {
        match i {
            0..=3 => a = a.wrapping_add((*byte as u32) << (8 * i)),
            4..=7 => b = b.wrapping_add((*byte as u32) << (8 * (i - 4))),
            _ => c = c.wrapping_add((*byte as u32) << (8 * (i - 7))),
        }
    }
    mix(a, b, c)
}

impl Hash2Run {
    // Port of the tuple, record, and local-fun field loops in
    // erts/emulator/beam/erl_term_hashing.c (make_hash2_helper), OTP-29.1.1.
    #[inline(always)]
    fn push_fields(
        hash: &mut u32,
        parent: Term,
        kind: FieldKind,
        next: Option<usize>,
        walk: &mut Hash2Walk<'_>,
        initial: bool,
    ) -> FieldProgress {
        match kind {
            FieldKind::Tuple => {
                // SAFETY: the owning heap remains live during the walk.
                let tuple = unsafe { parent.tuple_ref().unwrap() };
                if initial {
                    combine(hash, tuple.len() as u32, 0, H.wrapping_mul(9));
                }
                if tuple.is_empty() {
                    return FieldProgress::Common;
                }
                let mut index = next.unwrap_or(tuple.len() - 1);
                while index > 0 {
                    walk.stack.push(Term(tuple.words()[index]));
                    if walk.can_trap {
                        *walk.left -= 1;
                        if *walk.left <= 0 {
                            return FieldProgress::Yield(index - 1);
                        }
                    }
                    index -= 1;
                }
                FieldProgress::Compound(Term(tuple.words()[0]))
            }
            FieldKind::Record => {
                // SAFETY: the record instance and definition remain live during the walk.
                let record = unsafe { parent.record_ref().unwrap() };
                if initial {
                    combine(
                        hash,
                        record.len() as u32,
                        record.definition_hash(),
                        H.wrapping_mul(23),
                    );
                }
                if record.is_empty() {
                    return FieldProgress::Common;
                }
                let mut index = next.unwrap_or(record.len() - 1);
                while index > 0 {
                    walk.stack.push(record.value(index).unwrap());
                    if walk.can_trap {
                        *walk.left -= 1;
                        if *walk.left <= 0 {
                            return FieldProgress::Yield(index - 1);
                        }
                    }
                    index -= 1;
                }
                FieldProgress::Compound(record.value(0).unwrap())
            }
            FieldKind::Fun => {
                // SAFETY: the owning heap and process-lifetime fun entry remain live.
                let fun = unsafe { parent.fun_ref().unwrap() };
                match fun {
                    crate::FunRef::Local { entry, free_vars } => {
                        if initial {
                            let module = global_atoms().text(entry.module).unwrap();
                            combine(hash, free_vars.len() as u32, atom_hash(module), H);
                            combine(hash, entry.index, entry.old_uniq, H);
                        }
                        if free_vars.is_empty() {
                            return FieldProgress::Common;
                        }
                        let mut index = next.unwrap_or(free_vars.len() - 1);
                        while index > 0 {
                            walk.stack.push(Term(free_vars[index]));
                            if walk.can_trap {
                                *walk.left -= 1;
                                if *walk.left <= 0 {
                                    return FieldProgress::Yield(index - 1);
                                }
                            }
                            index -= 1;
                        }
                        FieldProgress::Compound(Term(free_vars[0]))
                    }
                    crate::FunRef::Export { entry } => {
                        if initial {
                            let module = global_atoms().text(entry.module).unwrap();
                            let function = global_atoms().text(entry.function).unwrap();
                            combine(hash, entry.arity as u32, atom_hash(module), H);
                            combine(hash, atom_hash(function), 0, H.wrapping_mul(14));
                        }
                        FieldProgress::Common
                    }
                }
            }
        }
    }

    // Port of the POS_BIG_SUBTAG and NEG_BIG_SUBTAG loops in make_hash2_helper,
    // erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
    #[inline(always)]
    fn push_big_digits(
        hash: &mut u32,
        term: Term,
        next: usize,
        walk: &mut Hash2Walk<'_>,
    ) -> Option<usize> {
        let header = term.header().unwrap();
        let digits = (header >> 6) as usize;
        let constant = H.wrapping_mul(if header & 63 == NEG_BIG { 10 } else { 11 });
        for index in next..digits {
            // SAFETY: index is below the digit count encoded in the live bignum header.
            let digit = unsafe { *term.raw_ptr().add(index + 1) };
            combine(hash, digit as u32, (digit >> 32) as u32, constant);
            if walk.can_trap {
                *walk.left -= 1;
                if *walk.left <= 0 {
                    return Some(index + 1);
                }
            }
        }
        None
    }

    // Port of flatmap and HAMT child pushes in make_hash2_helper,
    // erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
    #[inline(always)]
    fn push_map_child(child: Term, stack: &mut smallvec::SmallVec<[Term; 16]>) {
        if child.bits() & 3 == 1 {
            let mut pair = crate::ops::children(child);
            let key = pair.next().unwrap();
            let value = pair.next().unwrap();
            stack.push(HASH_MAP_PAIR);
            stack.push(value);
            stack.push(key);
        } else if child.header().is_some_and(|header| header & 63 == ARITY) {
            for leaf in crate::ops::children(child) {
                let mut pair = crate::ops::children(leaf);
                let key = pair.next().unwrap();
                let value = pair.next().unwrap();
                stack.push(HASH_MAP_PAIR);
                stack.push(value);
                stack.push(key);
            }
        } else {
            stack.push(child);
        }
    }

    #[inline(always)]
    fn push_flatmap_pairs(term: Term, next: usize, walk: &mut Hash2Walk<'_>) -> Option<usize> {
        crate::hamt::with_flatmap_arrays(term, |keys, values| {
            let mut index = next;
            while index != usize::MAX && index < keys.len() {
                walk.stack.push(HASH_MAP_PAIR);
                walk.stack.push(Term(values[index]));
                walk.stack.push(Term(keys[index]));
                if walk.can_trap {
                    *walk.left -= 1;
                    if *walk.left <= 0 {
                        return Some(index.checked_sub(1).unwrap_or(usize::MAX));
                    }
                }
                if index == 0 {
                    break;
                }
                index -= 1;
            }
            None
        })
        .expect("map branch distinguishes flatmaps from HAMTs")
    }

    #[inline(always)]
    fn push_map_children(
        mut children: crate::hamt::HashNodeChildren,
        walk: &mut Hash2Walk<'_>,
    ) -> Option<crate::hamt::HashNodeChildren> {
        while let Some(child) = children.next() {
            Self::push_map_child(child, walk.stack);
            if walk.can_trap {
                *walk.left -= 1;
                if *walk.left <= 0 {
                    return Some(children);
                }
            }
        }
        None
    }

    /// Start hashing `term`.
    #[inline]
    pub fn new(term: Term) -> Self {
        let simple = simple_hash(term);
        Self {
            hash: 0,
            term,
            stack: smallvec::SmallVec::new(),
            hash_xor_pairs: 0,
            resume: None,
            simple,
        }
    }

    /// Hash until done, or until `iterations` is used up (`None` never stops).
    // Port of erts/emulator/beam/erl_term_hashing.c:858 (make_hash2_helper), OTP-29.1.1.
    #[inline(always)]
    pub fn run(&mut self, iterations: Option<i64>) -> Hash2Progress {
        if let Some(hash) = self.simple {
            return Hash2Progress::Done { hash, used: 0 };
        }
        let can_trap = iterations.is_some();
        let max_iterations = iterations.unwrap_or(0);
        let mut left = max_iterations;
        let mut running = self.hash;
        let hash = &mut running;
        let mut walk = Hash2Walk {
            stack: &mut self.stack,
            left: &mut left,
            can_trap,
        };
        let mut hash_xor_pairs = self.hash_xor_pairs;
        let mut term = self.term;
        let mut direct = false;
        let mut start_common = false;
        if let Some(resume) = self.resume.take() {
            match resume {
                Hash2Resume::ListRun {
                    tail,
                    packed,
                    count,
                } => {
                    let Some(active) =
                        Self::list_by_value(hash, tail, packed, count, &mut walk, &mut self.resume)
                    else {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = term;
                        return Hash2Progress::Yield;
                    };
                    term = active;
                    direct = true;
                }
                Hash2Resume::Binary(job) => {
                    let BinaryJob {
                        term,
                        processed,
                        state,
                        buffer,
                    } = job;
                    if Self::binary_by_value(
                        hash,
                        term,
                        Some((processed, state, buffer)),
                        walk.left,
                        walk.can_trap,
                        &mut self.resume,
                    ) {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = term;
                        return Hash2Progress::Yield;
                    }
                    start_common = true;
                }
                Hash2Resume::Fields { parent, kind, next } => {
                    match Self::push_fields(hash, parent, kind, Some(next), &mut walk, false) {
                        FieldProgress::Yield(next) => {
                            self.hash = *hash;
                            self.hash_xor_pairs = hash_xor_pairs;
                            self.term = parent;
                            self.resume = Some(Hash2Resume::Fields { parent, kind, next });
                            return Hash2Progress::Yield;
                        }
                        FieldProgress::Compound(active) => {
                            term = active;
                            direct = true;
                        }
                        FieldProgress::Common => start_common = true,
                    }
                }
                Hash2Resume::Big { term: parent, next } => {
                    if let Some(next) = Self::push_big_digits(hash, parent, next, &mut walk) {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = parent;
                        self.resume = Some(Hash2Resume::Big { term: parent, next });
                        return Hash2Progress::Yield;
                    }
                    start_common = true;
                }
                Hash2Resume::FlatMap { term: parent, next } => {
                    if let Some(next) = Self::push_flatmap_pairs(parent, next, &mut walk) {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = parent;
                        self.resume = Some(Hash2Resume::FlatMap { term: parent, next });
                        return Hash2Progress::Yield;
                    }
                    start_common = true;
                }
                Hash2Resume::MapChildren {
                    term: parent,
                    children,
                } => {
                    if let Some(children) = Self::push_map_children(*children, &mut walk) {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = parent;
                        self.resume = Some(Hash2Resume::MapChildren {
                            term: parent,
                            children: Box::new(children),
                        });
                        return Hash2Progress::Yield;
                    }
                    start_common = true;
                }
                Hash2Resume::Common => start_common = true,
            }
        }
        loop {
            if direct {
                direct = false;
                if can_trap {
                    *walk.left -= 1;
                    if *walk.left <= 0 {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = term;
                        return Hash2Progress::Yield;
                    }
                }
                continue;
            }
            if !start_common {
                match primary_kind(term) {
                    TermKind::Atom => {
                        let value = global_atoms().hash(term.as_atom().unwrap()).unwrap();
                        if *hash == 0 {
                            *hash = value;
                        } else {
                            combine(hash, value, 0, H.wrapping_mul(3));
                        }
                    }
                    TermKind::Nil => {
                        if *hash == 0 {
                            *hash = 3_468_870_702;
                        } else {
                            combine(hash, 2, 0, H.wrapping_mul(2));
                        }
                    }
                    TermKind::Number => {
                        if let Some(n) = term.as_small() {
                            if (-(1 << 27)..(1 << 27)).contains(&n) {
                                let signed = n as i32;
                                if signed < 0 {
                                    combine(hash, signed.wrapping_neg() as u32, 0, H);
                                }
                                combine(hash, signed as u32, 0, H);
                            } else {
                                let mag = n.unsigned_abs();
                                combine(
                                    hash,
                                    mag as u32,
                                    (mag >> 32) as u32,
                                    H.wrapping_mul(if n < 0 { 10 } else { 11 }),
                                );
                            }
                        } else {
                            let header = term.header().unwrap();
                            if header & 63 == FLOAT {
                                // SAFETY: numeric header determines the object words.
                                let p = unsafe { term.raw_ptr() };
                                // SAFETY: float has one payload word.
                                let mut bits = unsafe { *p.add(1) };
                                if f64::from_bits(bits) == 0.0 {
                                    bits = 0;
                                }
                                combine(hash, (bits >> 32) as u32, bits as u32, H.wrapping_mul(12));
                            } else if (header & 63 == POS_BIG || header & 63 == NEG_BIG)
                                && let Some(next) = Self::push_big_digits(hash, term, 0, &mut walk)
                            {
                                self.hash = *hash;
                                self.hash_xor_pairs = hash_xor_pairs;
                                self.term = term;
                                self.resume = Some(Hash2Resume::Big { term, next });
                                return Hash2Progress::Yield;
                            }
                        }
                    }
                    TermKind::Pid | TermKind::Port | TermKind::Ref => {
                        match term.identity().unwrap() {
                            crate::Identity::Pid { index, .. } => {
                                combine(hash, index, 0, H.wrapping_mul(5))
                            }
                            crate::Identity::Port { id, .. } => {
                                combine(hash, id as u32, (id >> 32) as u32, H.wrapping_mul(6))
                            }
                            crate::Identity::Ref { ids, .. } => {
                                combine(hash, ids[0], 0, H.wrapping_mul(7))
                            }
                        }
                    }
                    TermKind::Record => {
                        match Self::push_fields(
                            hash,
                            term,
                            FieldKind::Record,
                            None,
                            &mut walk,
                            true,
                        ) {
                            FieldProgress::Yield(next) => {
                                self.hash = *hash;
                                self.hash_xor_pairs = hash_xor_pairs;
                                self.term = term;
                                self.resume = Some(Hash2Resume::Fields {
                                    parent: term,
                                    kind: FieldKind::Record,
                                    next,
                                });
                                return Hash2Progress::Yield;
                            }
                            FieldProgress::Compound(active) => {
                                term = active;
                                direct = true;
                            }
                            FieldProgress::Common => {}
                        }
                    }
                    TermKind::Fun => {
                        match Self::push_fields(hash, term, FieldKind::Fun, None, &mut walk, true) {
                            FieldProgress::Yield(next) => {
                                self.hash = *hash;
                                self.hash_xor_pairs = hash_xor_pairs;
                                self.term = term;
                                self.resume = Some(Hash2Resume::Fields {
                                    parent: term,
                                    kind: FieldKind::Fun,
                                    next,
                                });
                                return Hash2Progress::Yield;
                            }
                            FieldProgress::Compound(active) => {
                                term = active;
                                direct = true;
                            }
                            FieldProgress::Common => {}
                        }
                    }
                    TermKind::Tuple => {
                        match Self::push_fields(hash, term, FieldKind::Tuple, None, &mut walk, true)
                        {
                            FieldProgress::Yield(next) => {
                                self.hash = *hash;
                                self.hash_xor_pairs = hash_xor_pairs;
                                self.term = term;
                                self.resume = Some(Hash2Resume::Fields {
                                    parent: term,
                                    kind: FieldKind::Tuple,
                                    next,
                                });
                                return Hash2Progress::Yield;
                            }
                            FieldProgress::Compound(active) => {
                                term = active;
                                direct = true;
                            }
                            FieldProgress::Common => {}
                        }
                    }
                    TermKind::List => {
                        let Some(active) =
                            Self::list_by_value(hash, term, 0, 0, &mut walk, &mut self.resume)
                        else {
                            self.hash = *hash;
                            self.hash_xor_pairs = hash_xor_pairs;
                            self.term = term;
                            return Hash2Progress::Yield;
                        };
                        term = active;
                        direct = true;
                    }
                    TermKind::Bitstring => {
                        if Self::binary_by_value(
                            hash,
                            term,
                            None,
                            walk.left,
                            walk.can_trap,
                            &mut self.resume,
                        ) {
                            {
                                self.hash = *hash;
                                self.hash_xor_pairs = hash_xor_pairs;
                                self.term = term;
                                return Hash2Progress::Yield;
                            }
                        }
                    }
                    TermKind::Map => {
                        let header = term.header().unwrap();
                        match (header >> 6) & 3 {
                            0 => {
                                let size = crate::hamt::len(term);
                                combine(hash, size as u32, 0, H.wrapping_mul(16));
                                if size > 0 {
                                    let saved = *hash;
                                    walk.stack.push(Term(hash_xor_pairs as u64));
                                    walk.stack.push(Term(saved as u64));
                                    walk.stack.push(HASH_MAP_TAIL);
                                    *hash = 0;
                                    hash_xor_pairs = 0;
                                    if let Some(next) =
                                        Self::push_flatmap_pairs(term, size - 1, &mut walk)
                                    {
                                        self.hash = *hash;
                                        self.hash_xor_pairs = hash_xor_pairs;
                                        self.term = term;
                                        self.resume = Some(Hash2Resume::FlatMap { term, next });
                                        return Hash2Progress::Yield;
                                    }
                                }
                            }
                            1 => {
                                let children = crate::hamt::hash_node_children(term)
                                    .expect("bitmap node has direct HAMT children");
                                if let Some(children) = Self::push_map_children(children, &mut walk)
                                {
                                    self.hash = *hash;
                                    self.hash_xor_pairs = hash_xor_pairs;
                                    self.term = term;
                                    self.resume = Some(Hash2Resume::MapChildren {
                                        term,
                                        children: Box::new(children),
                                    });
                                    return Hash2Progress::Yield;
                                }
                            }
                            2 | 3 => {
                                let size = crate::hamt::len(term);
                                combine(hash, size as u32, 0, H.wrapping_mul(16));
                                if size > 0 {
                                    let saved = *hash;
                                    walk.stack.push(Term(hash_xor_pairs as u64));
                                    walk.stack.push(Term(saved as u64));
                                    walk.stack.push(HASH_MAP_TAIL);
                                    *hash = 0;
                                    hash_xor_pairs = 0;
                                    let children = crate::hamt::hash_node_children(term)
                                        .expect("HAMT head has direct children");
                                    if let Some(children) =
                                        Self::push_map_children(children, &mut walk)
                                    {
                                        self.hash = *hash;
                                        self.hash_xor_pairs = hash_xor_pairs;
                                        self.term = term;
                                        self.resume = Some(Hash2Resume::MapChildren {
                                            term,
                                            children: Box::new(children),
                                        });
                                        return Hash2Progress::Yield;
                                    }
                                }
                            }
                            _ => unreachable!("map header subtype is two bits"),
                        }
                    }
                    other => panic!("unsupported term kind in make_hash2: {other:?}"),
                }
            }
            start_common = false;
            if direct {
                direct = false;
                if can_trap {
                    *walk.left -= 1;
                    if *walk.left <= 0 {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = term;
                        return Hash2Progress::Yield;
                    }
                }
                continue;
            }
            if walk.stack.is_empty() {
                self.hash = *hash;
                self.hash_xor_pairs = hash_xor_pairs;
                return Hash2Progress::Done {
                    hash: *hash,
                    used: max_iterations - *walk.left,
                };
            }
            term = walk.stack.pop().unwrap();
            if term == HASH_MAP_PAIR {
                hash_xor_pairs ^= *hash;
                *hash = 0;
            } else if term == HASH_MAP_TAIL {
                *hash = walk.stack.pop().unwrap().word() as u32;
                combine(hash, hash_xor_pairs, 0, H.wrapping_mul(19));
                hash_xor_pairs = walk.stack.pop().unwrap().word() as u32;
            } else if can_trap {
                *walk.left -= 1;
                if *walk.left <= 0 {
                    self.hash = *hash;
                    self.hash_xor_pairs = hash_xor_pairs;
                    self.term = term;
                    return Hash2Progress::Yield;
                }
            }
            if term == HASH_MAP_PAIR || term == HASH_MAP_TAIL {
                if can_trap {
                    *walk.left -= 1;
                    if *walk.left <= 0 {
                        self.hash = *hash;
                        self.hash_xor_pairs = hash_xor_pairs;
                        self.term = term;
                        self.resume = Some(Hash2Resume::Common);
                        return Hash2Progress::Yield;
                    }
                }
                start_common = true;
            }
        }
    }

    #[inline(always)]
    fn list_by_value(
        hash: &mut u32,
        term: Term,
        packed: u32,
        count: u8,
        walk: &mut Hash2Walk<'_>,
        resume: &mut Option<Hash2Resume>,
    ) -> Option<Term> {
        let mut value = *hash;
        let active = Self::list(&mut value, term, packed, count, walk, resume);
        *hash = value;
        active
    }

    #[inline(always)]
    fn binary_by_value(
        hash: &mut u32,
        term: Term,
        resumed: Option<BinaryResume>,
        left: &mut i64,
        can_trap: bool,
        resume_out: &mut Option<Hash2Resume>,
    ) -> bool {
        let mut value = *hash;
        let trapped = Self::binary(&mut value, term, resumed, left, can_trap, resume_out);
        *hash = value;
        trapped
    }

    /// The byte-run loop of the list case. Returns whether it trapped part way.
    // Port of the `TAG_PRIMARY_LIST` case of `make_hash2_helper`,
    // erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
    #[inline(always)]
    fn list(
        hash: &mut u32,
        term: Term,
        mut packed: u32,
        mut count: u8,
        walk: &mut Hash2Walk<'_>,
        resume: &mut Option<Hash2Resume>,
    ) -> Option<Term> {
        let mut tail = term;
        // SAFETY: the list remains live throughout hashing.
        while let Some((head, next, next_is_cons)) = unsafe {
            tail.cons_ref()
                .map(|(head, next)| (head, next, next.word() & 3 == 1))
        } {
            let Some(byte) = head.as_small().filter(|n| (0..=255).contains(n)) else {
                break;
            };
            packed = (packed << 8) | byte as u32;
            count += 1;
            if count == 4 {
                combine(hash, packed, 0, H.wrapping_mul(4));
                packed = 0;
                count = 0;
            }
            tail = next;
            if walk.can_trap && next_is_cons {
                *walk.left -= 1;
                if *walk.left <= 0 {
                    *resume = Some(Hash2Resume::ListRun {
                        tail,
                        packed,
                        count,
                    });
                    return None;
                }
            }
        }
        if count != 0 {
            combine(hash, packed, 0, H.wrapping_mul(4));
        }
        // SAFETY: the list remains live throughout hashing.
        if let Some((head, next)) = unsafe { tail.cons_ref() } {
            walk.stack.push(next);
            Some(head)
        } else {
            Some(tail)
        }
    }

    /// The binary case. Returns whether it trapped part way.
    // Port of the `BIN_REF_SUBTAG`, `HEAP_BITS_SUBTAG` and `SUB_BITS_SUBTAG` case of
    // `make_hash2_helper`, erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
    fn binary(
        hash: &mut u32,
        term: Term,
        resumed: Option<BinaryResume>,
        left: &mut i64,
        can_trap: bool,
        resume_out: &mut Option<Hash2Resume>,
    ) -> bool {
        // SAFETY: source heap and binary backing remain live.
        let view = unsafe { term.binary_ref().unwrap() };
        let bit_len = view.bit_len();
        let size = (bit_len / 8) & 0xFFFF_FFFF;
        let bitsize = bit_len % 8;
        let iters_for_bin = ((size / BLOCK_HASH_BYTES_PER_ITER) as i64).max(1);
        let con = H.wrapping_mul(13).wrapping_add(*hash);

        if size == 0 && bitsize == 0 {
            *hash = con;
            return false;
        }

        if view.start_bit().is_multiple_of(8) {
            let mut scratch = Vec::new();
            let data = aligned_binary(&view, size, bitsize, &mut scratch);
            let (mut processed, mut state) = match resumed {
                Some((processed, state, None)) => (processed, state),
                Some((_, _, Some(_))) => unreachable!("aligned binary has no copy buffer"),
                None => {
                    if !can_trap || *left - iters_for_bin > 0 {
                        if can_trap {
                            *left -= iters_for_bin;
                        }
                        *hash = block_hash(&data[..size], con);
                        Self::binary_tail(hash, data, size, bitsize);
                        return false;
                    }
                    (0, (H, H, con))
                }
            };
            loop {
                let max_bytes = if *left <= 0 {
                    BLOCK_HASH_BYTES_PER_ITER
                } else {
                    (*left as usize).saturating_mul(BLOCK_HASH_BYTES_PER_ITER)
                };
                let bytes_left = size - processed;
                let even_left = bytes_left - bytes_left % BLOCK_HASH_BYTES_PER_ITER;
                let to_process = max_bytes.min(even_left);
                block_hash_buffer(&mut state, &data[processed..processed + to_process]);
                processed += to_process;
                *left -= ((to_process / BLOCK_HASH_BYTES_PER_ITER) as i64).max(1);
                if *left <= 0 {
                    *resume_out = Some(Hash2Resume::Binary(BinaryJob {
                        term,
                        processed,
                        state,
                        buffer: None,
                    }));
                    return true;
                }
                if size - processed < BLOCK_HASH_BYTES_PER_ITER {
                    break;
                }
            }
            *hash = block_hash_final_bytes(state, &data[processed..size], size);
            Self::binary_tail(hash, data, size, bitsize);
            return false;
        }

        if resumed.is_none() && (!can_trap || *left - iters_for_bin > 0) {
            let mut scratch = Vec::new();
            let data = aligned_binary(&view, size, bitsize, &mut scratch);
            if can_trap {
                *left -= iters_for_bin;
            }
            *hash = block_hash(&data[..size], con);
            Self::binary_tail(hash, data, size, bitsize);
            return false;
        }

        let was_resumed = resumed.is_some();
        let (mut processed, mut state, saved_buffer) = resumed.unwrap_or_else(|| {
            (
                0,
                (H, H, con),
                Some(vec![
                    0;
                    (size + usize::from(bitsize != 0))
                        .min(BINARY_BUFFER_SIZE)
                ]),
            )
        });
        let mut buffer = saved_buffer
            .unwrap_or_else(|| vec![0; (size + usize::from(bitsize != 0)).min(BINARY_BUFFER_SIZE)]);
        let nr_bits = size * 8 + bitsize;
        // Port of the bit-offset branch of make_hash2_helper, including its fixed-size
        // copy buffer, so a trap resumes from the next source window instead of copying
        // the full sub-binary again.
        loop {
            if was_resumed && size - processed < BLOCK_HASH_BYTES_PER_ITER {
                break;
            }
            let bytes_left = size - processed;
            let even_left = bytes_left - bytes_left % BLOCK_HASH_BYTES_PER_ITER;
            let to_process = BINARY_BUFFER_SIZE.min(even_left);
            let bits_left = nr_bits - processed * 8;
            let bits_to_copy = bits_left.min(BINARY_BUFFER_SIZE * 8);
            copy_bit_range(
                view.bytes(),
                view.start_bit() + processed * 8,
                &mut buffer,
                bits_to_copy,
            );
            block_hash_buffer(&mut state, &buffer[..to_process]);
            processed += to_process;
            *left -= ((to_process / BLOCK_HASH_BYTES_PER_ITER) as i64).max(1);
            if *left <= 0 {
                *resume_out = Some(Hash2Resume::Binary(BinaryJob {
                    term,
                    processed,
                    state,
                    buffer: Some(buffer),
                }));
                return true;
            }
            if size - processed < BLOCK_HASH_BYTES_PER_ITER {
                break;
            }
        }

        let nr_bytes = size + usize::from(bitsize != 0);
        let last_buffer_start = ((nr_bytes - 1) / BINARY_BUFFER_SIZE) * BINARY_BUFFER_SIZE;
        let buffer_offset = processed - last_buffer_start;
        let remaining = size - processed;
        *hash = block_hash_final_bytes(
            state,
            &buffer[buffer_offset..buffer_offset + remaining],
            size,
        );
        if bitsize > 0 {
            let last_byte_index = nr_bytes - last_buffer_start - 1;
            Self::binary_tail_byte(hash, buffer[last_byte_index], bitsize);
        }
        false
    }

    fn binary_tail(hash: &mut u32, data: &[u8], size: usize, bitsize: usize) {
        if bitsize > 0 {
            Self::binary_tail_byte(hash, data[size], bitsize);
        }
    }

    fn binary_tail_byte(hash: &mut u32, byte: u8, bitsize: usize) {
        combine(
            hash,
            bitsize as u32,
            (byte >> (8 - bitsize)) as u32,
            H.wrapping_mul(15),
        );
    }
}

/// Compute OTP's `make_hash2` for supported term kinds.
/// Port of `erts/emulator/beam/erl_term_hashing.c:858` (`make_hash2_helper`), OTP-29.1.1.
pub fn make_hash2(term: Term) -> u32 {
    match Hash2Run::new(term).run(None) {
        Hash2Progress::Done { hash, .. } => hash,
        Hash2Progress::Yield => unreachable!("an unbounded run never yields"),
    }
}
/// OTP `phash2/1`, using its fixed 27-bit range.
pub fn phash2(term: Term) -> u32 {
    make_hash2(term) & ((1 << 27) - 1)
}
/// OTP `phash2/2` range reduction (range must be nonzero).
pub fn phash2_range(term: Term, range: u64) -> Option<u32> {
    if range == 0 || range > (1_u64 << 32) {
        None
    } else if range == (1_u64 << 32) {
        Some(make_hash2(term))
    } else {
        Some(make_hash2(term) % range as u32)
    }
}

const F1: u32 = 268_440_163;
const F2: u32 = 268_439_161;
const F3: u32 = 268_435_459;
const F4: u32 = 268_436_141;
const F5: u32 = 268_438_633;
const F6: u32 = 268_437_017;
const F8: u32 = 268_437_511;
const F9: u32 = 268_439_627;
const F10: u32 = 268_440_479;
const F11: u32 = 268_440_577;
const F12: u32 = 268_440_581;
const F13: u32 = 268_440_593;
const F14: u32 = 268_440_611;
const F15: u32 = 268_440_629;

#[inline]
fn step(hash: &mut u32, value: u32, factor: u32) {
    for byte in value.to_le_bytes() {
        *hash = hash.wrapping_mul(factor).wrapping_add(byte as u32);
    }
}
enum HashJob {
    Visit(Term),
    TupleEnd(usize),
    RecordEnd(usize),
    ListTail(Term),
    ListEnd,
}

/// OTP's original portable 32-bit hash (`make_hash`).
/// Port of `erts/emulator/beam/erl_term_hashing.c:165` (`make_hash`), OTP-29.1.1.
pub fn make_hash(root: Term) -> u32 {
    let mut hash = 0_u32;
    let mut jobs = vec![HashJob::Visit(root)];
    while let Some(job) = jobs.pop() {
        match job {
            HashJob::TupleEnd(n) => hash = hash.wrapping_mul(F9).wrapping_add(n as u32),
            HashJob::RecordEnd(n) => hash = hash.wrapping_mul(F15).wrapping_add(n as u32),
            HashJob::ListEnd => hash = hash.wrapping_mul(F8),
            HashJob::ListTail(tail) => {
                if tail.classify() == TermKind::List {
                    jobs.push(HashJob::Visit(tail));
                } else {
                    jobs.push(HashJob::ListEnd);
                    jobs.push(HashJob::Visit(tail));
                }
            }
            HashJob::Visit(term) => match term.classify() {
                TermKind::Nil => hash = hash.wrapping_mul(F3).wrapping_add(1),
                TermKind::Atom => {
                    let text = global_atoms().text(term.as_atom().unwrap()).unwrap();
                    hash = hash.wrapping_mul(F1).wrapping_add(atom_hash(text));
                }
                TermKind::Number => {
                    if let Some(n) = term.as_small() {
                        let magnitude = n.unsigned_abs();
                        step(&mut hash, magnitude as u32, F2);
                        if magnitude >> 32 != 0 {
                            step(&mut hash, (magnitude >> 32) as u32, F2);
                        }
                        hash = hash.wrapping_mul(if n < 0 { F4 } else { F3 });
                    } else {
                        let header = term.header().unwrap();
                        // SAFETY: numeric header identifies initialized words.
                        let p = unsafe { term.raw_ptr() };
                        if header & 63 == FLOAT {
                            // SAFETY: float payload is one word.
                            let mut bits = unsafe { *p.add(1) };
                            if f64::from_bits(bits) == 0.0 {
                                bits = 0;
                            }
                            hash = hash
                                .wrapping_mul(F6)
                                .wrapping_add((bits as u32) ^ ((bits >> 32) as u32));
                        } else if header & 63 == POS_BIG || header & 63 == NEG_BIG {
                            let count = (header >> 6) as usize;
                            for i in 0..count {
                                // SAFETY: count is the bignum digit count.
                                let digit = unsafe { *p.add(i + 1) };
                                let bytes = digit.to_le_bytes();
                                let len = if i + 1 == count && digit >> 32 == 0 {
                                    4
                                } else {
                                    8
                                };
                                for byte in &bytes[..len] {
                                    hash = hash.wrapping_mul(F2).wrapping_add(*byte as u32);
                                }
                            }
                            hash = hash.wrapping_mul(if header & 63 == NEG_BIG { F4 } else { F3 });
                        }
                    }
                }
                TermKind::Pid | TermKind::Port | TermKind::Ref => match term.identity().unwrap() {
                    crate::Identity::Pid { index, .. } => {
                        step(&mut hash, index, F5);
                        hash = hash.wrapping_mul(F6);
                    }
                    crate::Identity::Port { id, .. } => {
                        if id >> 32 != 0 {
                            step(&mut hash, (id >> 32) as u32, F11);
                        }
                        step(&mut hash, id as u32, F9);
                        hash = hash.wrapping_mul(F10);
                    }
                    crate::Identity::Ref { ids, .. } => {
                        step(&mut hash, ids[0], F9);
                        hash = hash.wrapping_mul(F10);
                    }
                },
                TermKind::Bitstring => {
                    // SAFETY: backing memory remains live throughout hashing.
                    let view = unsafe { term.binary_ref().unwrap() };
                    let whole = view.bit_len() / 8;
                    for i in 0..whole {
                        let bit = view.start_bit() + i * 8;
                        let byte = if bit % 8 == 0 {
                            view.bytes()[bit / 8]
                        } else {
                            (view.bytes()[bit / 8] << (bit % 8))
                                | (view.bytes()[bit / 8 + 1] >> (8 - bit % 8))
                        };
                        hash = hash.wrapping_mul(F1).wrapping_add(byte as u32);
                    }
                    let tail = view.bit_len() % 8;
                    if tail > 0 {
                        let mut bits = 0_u32;
                        for i in 0..tail {
                            let bit = view.start_bit() + whole * 8 + i;
                            bits = (bits << 1)
                                | (((view.bytes()[bit / 8] >> (7 - bit % 8)) & 1) as u32);
                        }
                        hash = hash
                            .wrapping_mul(F1)
                            .wrapping_add(bits)
                            .wrapping_mul(F12)
                            .wrapping_add(tail as u32);
                    }
                    hash = hash.wrapping_mul(F4).wrapping_add(whole as u32);
                }
                TermKind::Tuple => {
                    // SAFETY: tuple remains live during hashing.
                    let tuple = unsafe { term.tuple_ref().unwrap() };
                    jobs.push(HashJob::TupleEnd(tuple.len()));
                    for i in (0..tuple.len()).rev() {
                        jobs.push(HashJob::Visit(tuple.get(i).unwrap()));
                    }
                }
                TermKind::Record => {
                    // SAFETY: record remains live during hashing.
                    let view = unsafe { term.record_ref().unwrap() };
                    jobs.push(HashJob::RecordEnd(view.len() + 1));
                    for i in (0..view.len()).rev() {
                        jobs.push(HashJob::Visit(view.value(i).unwrap()));
                    }
                    // SAFETY: native record word one is its definition term.
                    jobs.push(HashJob::Visit(Term(unsafe { *term.raw_ptr().add(1) })));
                }
                TermKind::List => {
                    let mut cursor = term;
                    loop {
                        // SAFETY: list cells remain live during hashing.
                        let (head, tail) = unsafe { cursor.cons_ref().unwrap() };
                        if let Some(byte) = head.as_small().filter(|n| (0..=255).contains(n)) {
                            hash = hash.wrapping_mul(F2).wrapping_add(byte as u32);
                            if tail.classify() != TermKind::List {
                                jobs.push(HashJob::ListEnd);
                                jobs.push(HashJob::Visit(tail));
                                break;
                            }
                            cursor = tail;
                        } else {
                            jobs.push(HashJob::ListTail(tail));
                            jobs.push(HashJob::Visit(head));
                            break;
                        }
                    }
                }
                TermKind::Map => {
                    hash = hash
                        .wrapping_mul(F13)
                        .wrapping_add(F14)
                        .wrapping_add(make_hash2(term))
                }
                TermKind::Fun => {
                    // SAFETY: the fun entry remains retained by its heap.
                    match unsafe { term.fun_ref().unwrap() } {
                        crate::FunRef::Local { entry, free_vars } => {
                            hash = hash.wrapping_mul(F10).wrapping_add(free_vars.len() as u32);
                            hash = hash.wrapping_mul(F1).wrapping_add(atom_hash(
                                global_atoms().text(entry.module).unwrap(),
                            ));
                            hash = hash.wrapping_mul(F2).wrapping_add(entry.index);
                            hash = hash.wrapping_mul(F2).wrapping_add(entry.old_uniq);
                            for value in free_vars.iter().rev() {
                                jobs.push(HashJob::Visit(Term(*value)));
                            }
                        }
                        crate::FunRef::Export { entry } => {
                            hash = hash.wrapping_mul(F11).wrapping_add(entry.arity as u32);
                            hash = hash.wrapping_mul(F1).wrapping_add(atom_hash(
                                global_atoms().text(entry.module).unwrap(),
                            ));
                            hash = hash.wrapping_mul(F1).wrapping_add(atom_hash(
                                global_atoms().text(entry.function).unwrap(),
                            ));
                        }
                    }
                }
                other => panic!("unsupported term kind in make_hash: {other:?}"),
            },
        }
    }
    hash
}
/// OTP `erlang:phash/2` in its one-based range, including the 2^32 case.
pub fn phash(term: Term, range: u64) -> Option<u64> {
    if range == 0 || range > (1_u64 << 32) {
        None
    } else {
        Some(1 + (make_hash(term) as u64 % range))
    }
}
