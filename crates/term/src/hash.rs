//! Stable external `phash2` hashing for implemented term kinds.
use crate::{FLOAT, NEG_BIG, POS_BIG, Term, TermKind, global_atoms};
const H: u32 = 0x9e37_79b9;
type BinaryResume = (usize, (u32, u32, u32), Option<Vec<u8>>);

// Port of erts/emulator/beam/erl_term_hashing.c:426 (MIX), OTP-29.1.1.
#[inline]
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
#[inline]
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

enum Job {
    Visit(Term),
    Reset,
    Xor,
    Finish(u32),
    /// A run of bytes in a list that trapped part way: the next cons and the packed word.
    ListRun {
        tail: Term,
        packed: u32,
        count: u32,
    },
    /// A binary hashed in several slices: the bytes done and the block hash state.
    Binary {
        term: Term,
        processed: usize,
        state: (u32, u32, u32),
        buffer: Option<Vec<u8>>,
    },
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
    stack: smallvec::SmallVec<[Job; 16]>,
    xors: smallvec::SmallVec<[u32; 4]>,
    simple: Option<u32>,
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

/// `make_hash2` of a term that hashes without a work stack (small integers, atoms, `[]`, pids
/// and ports); `None` for everything else.
// Port of erts/emulator/beam/erl_term_hashing.c (make_hash2_helper, the immediate cases),
// OTP-29.1.1.
pub fn hash2_immediate(term: Term) -> Option<u32> {
    simple_hash(term)
}

fn simple_hash(term: Term) -> Option<u32> {
    if let Some(n) = term.as_small() {
        return Some(small_hash(n));
    }
    if let Some(atom) = term.as_atom() {
        return Some(global_atoms().hash(atom).unwrap());
    }
    if term == Term::NIL {
        return Some(3_468_870_702);
    }
    if let Some((index, _)) = term.as_pid() {
        let mut hash = 0;
        combine(&mut hash, index, 0, H.wrapping_mul(5));
        return Some(hash);
    }
    if let Some(id) = term.as_port() {
        let mut hash = 0;
        combine(&mut hash, id as u32, (id >> 32) as u32, H.wrapping_mul(6));
        return Some(hash);
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
    /// Start hashing `term`.
    pub fn new(term: Term) -> Self {
        let simple = simple_hash(term);
        let mut stack: smallvec::SmallVec<[Job; 16]> = smallvec::SmallVec::new();
        if simple.is_none() {
            stack.push(Job::Visit(term));
        }
        Self {
            hash: 0,
            stack,
            xors: smallvec::SmallVec::new(),
            simple,
        }
    }

    /// Hash until done, or until `iterations` is used up (`None` never stops).
    // Port of erts/emulator/beam/erl_term_hashing.c:858 (make_hash2_helper), OTP-29.1.1.
    pub fn run(&mut self, iterations: Option<i64>) -> Hash2Progress {
        if let Some(hash) = self.simple {
            return Hash2Progress::Done { hash, used: 0 };
        }
        let can_trap = iterations.is_some();
        let max_iterations = iterations.unwrap_or(0);
        let mut left = max_iterations;
        let hash = &mut self.hash;
        let stack = &mut self.stack;
        let xors = &mut self.xors;
        while let Some(job) = stack.pop() {
            // Each job is one loop iteration of the erts loop, plus its inner iterations.
            let mut ticks = 1_i64;
            let mut marker = false;
            match job {
                Job::Reset => {
                    *hash = 0;
                    ticks = 0;
                }
                Job::Xor => {
                    *xors.last_mut().unwrap() ^= *hash;
                    marker = true;
                }
                Job::Finish(saved) => {
                    let pairs = xors.pop().unwrap();
                    *hash = saved;
                    combine(hash, pairs, 0, H.wrapping_mul(19));
                    marker = true;
                }
                Job::ListRun {
                    tail,
                    packed,
                    count,
                } => {
                    if Self::list(hash, stack, tail, packed, count, &mut left, can_trap) {
                        return Hash2Progress::Yield;
                    }
                }
                Job::Binary {
                    term,
                    processed,
                    state,
                    buffer,
                } => {
                    if Self::binary(
                        hash,
                        stack,
                        term,
                        Some((processed, state, buffer)),
                        &mut left,
                        can_trap,
                    ) {
                        return Hash2Progress::Yield;
                    }
                }
                Job::Visit(term) => match term.classify() {
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
                            // SAFETY: numeric header determines the object words.
                            let p = unsafe { term.raw_ptr() };
                            if header & 63 == FLOAT {
                                // SAFETY: float has one payload word.
                                let mut bits = unsafe { *p.add(1) };
                                if f64::from_bits(bits) == 0.0 {
                                    bits = 0;
                                }
                                combine(hash, (bits >> 32) as u32, bits as u32, H.wrapping_mul(12));
                            } else if header & 63 == POS_BIG || header & 63 == NEG_BIG {
                                let con =
                                    H.wrapping_mul(if header & 63 == NEG_BIG { 10 } else { 11 });
                                let digits = (header >> 6) as usize;
                                for i in 0..digits {
                                    // SAFETY: bignum header gives the digit count.
                                    let digit = unsafe { *p.add(i + 1) };
                                    combine(hash, digit as u32, (digit >> 32) as u32, con);
                                }
                                ticks += digits as i64;
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
                        // SAFETY: source record and definition remain live during hashing.
                        let record = unsafe { term.record_ref().unwrap() };
                        combine(
                            hash,
                            record.len() as u32,
                            record.definition_hash(),
                            H.wrapping_mul(23),
                        );
                        for i in (0..record.len()).rev() {
                            stack.push(Job::Visit(record.value(i).unwrap()));
                        }
                        ticks += record.len().saturating_sub(1) as i64;
                    }
                    TermKind::Fun => {
                        // SAFETY: the owning heap retains the referenced entry.
                        match unsafe { term.fun_ref().unwrap() } {
                            crate::FunRef::Local { entry, free_vars } => {
                                let module = global_atoms().text(entry.module).unwrap();
                                combine(hash, free_vars.len() as u32, atom_hash(module), H);
                                combine(hash, entry.index, entry.old_uniq, H);
                                for value in free_vars.iter().rev() {
                                    stack.push(Job::Visit(Term(*value)));
                                }
                                ticks += free_vars.len().saturating_sub(1) as i64;
                            }
                            crate::FunRef::Export { entry } => {
                                let module = global_atoms().text(entry.module).unwrap();
                                let function = global_atoms().text(entry.function).unwrap();
                                combine(hash, entry.arity as u32, atom_hash(module), H);
                                combine(hash, atom_hash(function), 0, H.wrapping_mul(14));
                            }
                        }
                    }
                    TermKind::Tuple => {
                        // SAFETY: source heap remains live throughout hashing.
                        let tuple = unsafe { term.tuple_ref().unwrap() };
                        combine(hash, tuple.len() as u32, 0, H.wrapping_mul(9));
                        for i in (0..tuple.len()).rev() {
                            stack.push(Job::Visit(tuple.get(i).unwrap()));
                        }
                        ticks += tuple.len().saturating_sub(1) as i64;
                    }
                    TermKind::List => {
                        if Self::list(hash, stack, term, 0, 0, &mut left, can_trap) {
                            return Hash2Progress::Yield;
                        }
                    }
                    TermKind::Bitstring => {
                        if Self::binary(hash, stack, term, None, &mut left, can_trap) {
                            return Hash2Progress::Yield;
                        }
                    }
                    TermKind::Map => {
                        // Port of erts/emulator/beam/erl_term_hashing.c:1130-1215
                        // (make_hash2_helper map branch), OTP-29.1.1.
                        let n = crate::hamt::len(term);
                        combine(hash, n as u32, 0, H.wrapping_mul(16));
                        if n > 0 {
                            let saved = *hash;
                            xors.push(0);
                            stack.push(Job::Finish(saved));
                            // Port of the direct flatmap array loop in
                            // erts/emulator/beam/erl_term_hashing.c (make_hash2_helper, OTP-29.1.1).
                            if term.is_hashmap() {
                                for (key, value) in crate::hamt::PairIter::new(term) {
                                    stack.push(Job::Xor);
                                    stack.push(Job::Visit(value));
                                    stack.push(Job::Visit(key));
                                    stack.push(Job::Reset);
                                }
                            } else {
                                crate::hamt::with_flatmap_arrays(term, |keys, values| {
                                    for index in (0..keys.len()).rev() {
                                        stack.push(Job::Xor);
                                        stack.push(Job::Visit(Term(values[index])));
                                        stack.push(Job::Visit(Term(keys[index])));
                                        stack.push(Job::Reset);
                                    }
                                })
                                .expect("map branch distinguishes flatmaps from HAMTs");
                            }
                            ticks += n as i64;
                        }
                    }
                    other => panic!("unsupported term kind in make_hash2: {other:?}"),
                },
            }
            if can_trap {
                if stack.is_empty() && !marker {
                    break;
                }
                left -= ticks;
                if left <= 0 && !stack.is_empty() {
                    return Hash2Progress::Yield;
                }
            }
        }
        Hash2Progress::Done {
            hash: *hash,
            used: max_iterations - left,
        }
    }

    /// The byte-run loop of the list case. Returns whether it trapped part way.
    // Port of the `TAG_PRIMARY_LIST` case of `make_hash2_helper`,
    // erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
    fn list(
        hash: &mut u32,
        stack: &mut smallvec::SmallVec<[Job; 16]>,
        term: Term,
        mut packed: u32,
        mut count: u32,
        left: &mut i64,
        can_trap: bool,
    ) -> bool {
        let mut tail = term;
        // SAFETY: the list remains live throughout hashing.
        while let Some((head, next, next_is_cons)) = unsafe {
            tail.cons_ref()
                .map(|(head, next)| (head, next, next.cons_ref().is_some()))
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
            if can_trap && next_is_cons {
                *left -= 1;
                if *left <= 0 {
                    stack.push(Job::ListRun {
                        tail,
                        packed,
                        count,
                    });
                    return true;
                }
            }
        }
        if count != 0 {
            combine(hash, packed, 0, H.wrapping_mul(4));
        }
        // SAFETY: the list remains live throughout hashing.
        if let Some((head, next)) = unsafe { tail.cons_ref() } {
            stack.push(Job::Visit(next));
            stack.push(Job::Visit(head));
        } else {
            stack.push(Job::Visit(tail));
        }
        false
    }

    /// The binary case. Returns whether it trapped part way.
    // Port of the `BIN_REF_SUBTAG`, `HEAP_BITS_SUBTAG` and `SUB_BITS_SUBTAG` case of
    // `make_hash2_helper`, erts/emulator/beam/erl_term_hashing.c, OTP-29.1.1.
    fn binary(
        hash: &mut u32,
        stack: &mut smallvec::SmallVec<[Job; 16]>,
        term: Term,
        resumed: Option<BinaryResume>,
        left: &mut i64,
        can_trap: bool,
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
                    stack.push(Job::Binary {
                        term,
                        processed,
                        state,
                        buffer: None,
                    });
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
                stack.push(Job::Binary {
                    term,
                    processed,
                    state,
                    buffer: Some(buffer),
                });
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
