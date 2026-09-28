//! Stable external `phash2` hashing for implemented term kinds.
use crate::{FLOAT, NEG_BIG, POS_BIG, Term, TermKind, global_atoms};
const H: u32 = 0x9e37_79b9;

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
}
/// Compute OTP's `make_hash2` for supported term kinds.
/// Port of `erts/emulator/beam/erl_term_hashing.c:858` (`make_hash2_helper`), OTP-29.1.1.
pub fn make_hash2(term: Term) -> u32 {
    if let Some(n) = term.as_small() {
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
        return hash;
    }
    if let Some(atom) = term.as_atom() {
        return global_atoms().hash(atom).unwrap();
    }
    if term == Term::NIL {
        return 3_468_870_702;
    }
    if let Some((index, _)) = term.as_pid() {
        let mut hash = 0;
        combine(&mut hash, index, 0, H.wrapping_mul(5));
        return hash;
    }
    if let Some(id) = term.as_port() {
        let mut hash = 0;
        combine(&mut hash, id as u32, (id >> 32) as u32, H.wrapping_mul(6));
        return hash;
    }
    let mut hash = 0_u32;
    let mut stack = vec![Job::Visit(term)];
    let mut xors = Vec::new();
    while let Some(job) = stack.pop() {
        match job {
            Job::Reset => hash = 0,
            Job::Xor => *xors.last_mut().unwrap() ^= hash,
            Job::Finish(saved) => {
                let pairs = xors.pop().unwrap();
                hash = saved;
                combine(&mut hash, pairs, 0, H.wrapping_mul(19));
            }
            Job::Visit(term) => match term.classify() {
                TermKind::Atom => {
                    let value = global_atoms().hash(term.as_atom().unwrap()).unwrap();
                    if hash == 0 {
                        hash = value;
                    } else {
                        combine(&mut hash, value, 0, H.wrapping_mul(3));
                    }
                }
                TermKind::Nil => {
                    if hash == 0 {
                        hash = 3_468_870_702;
                    } else {
                        combine(&mut hash, 2, 0, H.wrapping_mul(2));
                    }
                }
                TermKind::Number => {
                    if let Some(n) = term.as_small() {
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
                            combine(
                                &mut hash,
                                (bits >> 32) as u32,
                                bits as u32,
                                H.wrapping_mul(12),
                            );
                        } else if header & 63 == POS_BIG || header & 63 == NEG_BIG {
                            let con = H.wrapping_mul(if header & 63 == NEG_BIG { 10 } else { 11 });
                            for i in 0..(header >> 6) as usize {
                                // SAFETY: bignum header gives the digit count.
                                let digit = unsafe { *p.add(i + 1) };
                                combine(&mut hash, digit as u32, (digit >> 32) as u32, con);
                            }
                        }
                    }
                }
                TermKind::Pid | TermKind::Port | TermKind::Ref => match term.identity().unwrap() {
                    crate::Identity::Pid { index, .. } => {
                        combine(&mut hash, index, 0, H.wrapping_mul(5))
                    }
                    crate::Identity::Port { id, .. } => {
                        combine(&mut hash, id as u32, (id >> 32) as u32, H.wrapping_mul(6))
                    }
                    crate::Identity::Ref { ids, .. } => {
                        combine(&mut hash, ids[0], 0, H.wrapping_mul(7))
                    }
                },
                TermKind::Record => {
                    // SAFETY: source record and definition remain live during hashing.
                    let record = unsafe { term.record_ref().unwrap() };
                    combine(
                        &mut hash,
                        record.len() as u32,
                        record.definition_hash(),
                        H.wrapping_mul(23),
                    );
                    for i in (0..record.len()).rev() {
                        stack.push(Job::Visit(record.value(i).unwrap()));
                    }
                }
                TermKind::Fun => {
                    // SAFETY: the owning heap retains the referenced entry.
                    match unsafe { term.fun_ref().unwrap() } {
                        crate::FunRef::Local { entry, free_vars } => {
                            let module = global_atoms().text(entry.module).unwrap();
                            combine(&mut hash, free_vars.len() as u32, atom_hash(&module), H);
                            combine(&mut hash, entry.index, entry.old_uniq, H);
                            for value in free_vars.iter().rev() {
                                stack.push(Job::Visit(Term(*value)));
                            }
                        }
                        crate::FunRef::Export { entry } => {
                            let module = global_atoms().text(entry.module).unwrap();
                            let function = global_atoms().text(entry.function).unwrap();
                            combine(&mut hash, entry.arity as u32, atom_hash(&module), H);
                            combine(&mut hash, atom_hash(&function), 0, H.wrapping_mul(14));
                        }
                    }
                }
                TermKind::Tuple => {
                    // SAFETY: source heap remains live throughout hashing.
                    let tuple = unsafe { term.tuple_ref().unwrap() };
                    combine(&mut hash, tuple.len() as u32, 0, H.wrapping_mul(9));
                    for i in (0..tuple.len()).rev() {
                        stack.push(Job::Visit(tuple.get(i).unwrap()));
                    }
                }
                TermKind::List => {
                    let mut tail = term;
                    let mut packed = 0_u32;
                    let mut count = 0;
                    // SAFETY: the list remains live throughout hashing.
                    while let Some((head, next)) = unsafe { tail.cons_ref() } {
                        if let Some(byte) = head.as_small().filter(|n| (0..=255).contains(n)) {
                            packed = (packed << 8) | byte as u32;
                            count += 1;
                            if count == 4 {
                                combine(&mut hash, packed, 0, H.wrapping_mul(4));
                                packed = 0;
                                count = 0;
                            }
                            tail = next;
                        } else {
                            break;
                        }
                    }
                    if count != 0 {
                        combine(&mut hash, packed, 0, H.wrapping_mul(4));
                    }
                    // SAFETY: the list remains live throughout hashing.
                    if let Some((head, next)) = unsafe { tail.cons_ref() } {
                        stack.push(Job::Visit(next));
                        stack.push(Job::Visit(head));
                    } else {
                        stack.push(Job::Visit(tail));
                    }
                }
                TermKind::Bitstring => {
                    // SAFETY: source heap and binary backing remain live.
                    let view = unsafe { term.binary_ref().unwrap() };
                    let mut aligned = Vec::new();
                    let data = if view.start_bit() % 8 == 0 {
                        &view.bytes()[view.start_bit() / 8
                            ..view.start_bit() / 8 + view.bit_len().div_ceil(8)]
                    } else {
                        aligned.resize(view.bit_len().div_ceil(8), 0);
                        for i in 0..view.bit_len() {
                            let bit = (view.bytes()[(view.start_bit() + i) / 8]
                                >> (7 - (view.start_bit() + i) % 8))
                                & 1;
                            aligned[i / 8] |= bit << (7 - i % 8);
                        }
                        &aligned
                    };
                    let con = H.wrapping_mul(13).wrapping_add(hash);
                    if view.bit_len() == 0 {
                        hash = con;
                    } else {
                        let whole = view.bit_len() / 8;
                        hash = block_hash(&data[..whole], con);
                        let tail = view.bit_len() % 8;
                        if tail != 0 {
                            combine(
                                &mut hash,
                                tail as u32,
                                (data[whole] >> (8 - tail)) as u32,
                                H.wrapping_mul(15),
                            );
                        }
                    }
                }
                TermKind::Map => {
                    // Port of erts/emulator/beam/erl_term_hashing.c:1130-1215
                    // (make_hash2_helper map branch), OTP-29.1.1.
                    let n = crate::hamt::len(term);
                    combine(&mut hash, n as u32, 0, H.wrapping_mul(16));
                    if n > 0 {
                        let saved = hash;
                        xors.push(0);
                        stack.push(Job::Finish(saved));
                        for (key, value) in crate::hamt::PairIter::new(term) {
                            stack.push(Job::Xor);
                            stack.push(Job::Visit(value));
                            stack.push(Job::Visit(key));
                            stack.push(Job::Reset);
                        }
                    }
                }
                other => panic!("unsupported term kind in make_hash2: {other:?}"),
            },
        }
    }
    hash
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
                    hash = hash.wrapping_mul(F1).wrapping_add(atom_hash(&text));
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
                                &global_atoms().text(entry.module).unwrap(),
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
                                &global_atoms().text(entry.module).unwrap(),
                            ));
                            hash = hash.wrapping_mul(F1).wrapping_add(atom_hash(
                                &global_atoms().text(entry.function).unwrap(),
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
