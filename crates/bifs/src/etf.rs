//! ETF BIFs over live process heap terms.
// Port of erts/emulator/beam/external.c (external term sizing, encoding, and decoding), OTP-29.1.1.

use std::cmp::Ordering;
use std::io::Write;
use std::sync::{Arc, OnceLock};

use arinsal_etf::DecodedSizeWalk;
use arinsal_term::{
    Atom, BinaryOwner, ConsListBuilder, ExportEntry, FunEntry, FunRef, HeapAlloc, HeapReservation,
    HeapReservationState, Identity, Node, OwnedBinaryRef, RefcBinary, Term, TermBuilder, TermKind,
    atoms, binary_owner, cmp_exact, flat_key_cmp, global_atoms, hashmap_from_ks_and_vs_extra,
    writable_finalize, writable_resize_private,
};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use smallvec::SmallVec;

use crate::pure::{Heap, integer, make_list, tuple_build};
use crate::{BifError, Ctx};

static LOCAL_NODE_HASH: OnceLock<u32> = OnceLock::new();
// Port of erts/emulator/beam/external.c:1768-1769, OTP-29.1.1.
const B2T_MAX_DIRECT_UNCOMPRESSED_SIZE: usize = 32 * 1024 * 1024;

// Port of erts/emulator/beam/external.c:134-194, OTP-29.1.1.
fn local_node_hash() -> u32 {
    *LOCAL_NODE_HASH.get_or_init(|| {
        let uname = rustix::system::uname();
        let hostname = uname.nodename().to_bytes();
        let hostname = &hostname[..hostname.len().min(255)];
        let pid = std::process::id().to_string();
        let offset =
            crate::time_offset_nanos_value().expect("the system time offset is available") as i64;
        let mut node_id = Vec::with_capacity(8 + hostname.len() + pid.len());
        node_id.extend_from_slice(&offset.to_le_bytes());
        node_id.extend_from_slice(hostname);
        node_id.extend_from_slice(pid.as_bytes());
        block_hash(&node_id, crate::monotonic_time_raw_nanos() as u32)
    })
}

/// Incremental Jenkins block hash used by `LOCAL_EXT`.
// Port of erts_block_hash_init/erts_block_hash in
// erts/emulator/beam/erl_term_hashing.c:450-577, OTP-29.1.1.
struct BlockHashWalk {
    a: u32,
    b: u32,
    c: u32,
    length: usize,
    cursor: usize,
    hash: Option<u32>,
}

impl BlockHashWalk {
    fn new(length: usize, initial: u32) -> Self {
        Self {
            a: 0x9e37_79b9,
            b: 0x9e37_79b9,
            c: initial,
            length,
            cursor: 0,
            hash: None,
        }
    }

    fn step(&mut self, bytes: &[u8], budget: usize) -> (bool, usize) {
        if self.hash.is_some() {
            return (true, 0);
        }
        debug_assert_eq!(bytes.len(), self.length);
        let remaining = self.length - self.cursor;
        let (full, yields) = if budget < remaining {
            let full = budget / 12 * 12;
            if remaining > full + 12 {
                (full + 12, true)
            } else {
                (remaining - remaining % 12, false)
            }
        } else {
            (remaining - remaining % 12, false)
        };
        let end = self.cursor + full;
        let (chunks, remaining_chunks) = bytes[self.cursor..end].as_chunks::<12>();
        debug_assert!(remaining_chunks.is_empty());
        for chunk in chunks {
            self.a = self
                .a
                .wrapping_add(u32::from_le_bytes(chunk[0..4].try_into().unwrap()));
            self.b = self
                .b
                .wrapping_add(u32::from_le_bytes(chunk[4..8].try_into().unwrap()));
            self.c = self
                .c
                .wrapping_add(u32::from_le_bytes(chunk[8..12].try_into().unwrap()));
            (self.a, self.b, self.c) = block_hash_mix(self.a, self.b, self.c);
        }
        self.cursor = end;
        if yields {
            return (false, full);
        }

        let remaining_bytes = &bytes[self.cursor..];
        self.c = self.c.wrapping_add(self.length as u32);
        for (index, byte) in remaining_bytes.iter().enumerate() {
            match index {
                0..=3 => self.a = self.a.wrapping_add((*byte as u32) << (8 * index)),
                4..=7 => self.b = self.b.wrapping_add((*byte as u32) << (8 * (index - 4))),
                _ => self.c = self.c.wrapping_add((*byte as u32) << (8 * (index - 7))),
            }
        }
        self.cursor = self.length;
        self.c = block_hash_mix(self.a, self.b, self.c).2;
        self.hash = Some(self.c);
        (true, full + remaining_bytes.len())
    }
}

fn block_hash(bytes: &[u8], initial: u32) -> u32 {
    let mut walk = BlockHashWalk::new(bytes.len(), initial);
    let (done, _) = walk.step(bytes, usize::MAX);
    debug_assert!(done);
    walk.hash.expect("unlimited block hash completes")
}

#[inline]
fn block_hash_mix(mut a: u32, mut b: u32, mut c: u32) -> (u32, u32, u32) {
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

// Port of erts/emulator/beam/external.c:4046-4105, OTP-29.1.1.
fn local_term_hash(bytes: &[u8]) -> u32 {
    block_hash(bytes, local_node_hash())
}

pub(super) fn lookup<V: crate::BifTableVisitor>(
    module: &str,
    name: &str,
    arity: u8,
    v: &mut V,
) -> Option<V::Output> {
    let f = match (module, name, arity) {
        ("erlang", "term_to_binary", 1 | 2) => v.entry::<word_bodies::term_to_binary>(),
        ("erlang", "term_to_iovec", 1 | 2) => v.entry::<word_bodies::term_to_iovec>(),
        ("erlang", "external_size", 1 | 2) => v.entry::<word_bodies::external_size>(),
        ("erlang", "binary_to_term", 1 | 2) => v.entry::<word_bodies::binary_to_term>(),
        _ => return None,
    };
    arinsal_spec::bif_lookup(module, name, arity).map(|_| f)
}

#[derive(Default, Clone, Copy)]
struct EncodeOpts {
    minor: u8,
    compressed: Option<u8>,
    deterministic: bool,
    /// `term_to_binary(Term, [local])`. Port of external.c LOCAL_EXT, OTP-29.1.1.
    local: bool,
    local_node: Option<(arinsal_term::Atom, u32)>,
}

fn atom_text(term: Term) -> Option<&'static str> {
    global_atoms().text(term.as_atom()?)
}

// Port of erts/emulator/beam/external.c:1480-1535 (parse_t2b_opts), OTP-29.1.1.
fn options(term: Option<Term>) -> Result<EncodeOpts, BifError> {
    let mut opts = EncodeOpts {
        minor: 2,
        ..EncodeOpts::default()
    };
    let Some(mut tail) = term else {
        return Ok(opts);
    };
    while tail != Term::NIL {
        // SAFETY: BIF arguments remain on stable live heaps throughout this call.
        let (head, next) = unsafe { tail.cons_ref() }.ok_or(BifError::BADARG)?;
        tail = next;
        match head.as_atom() {
            Some(atoms::COMPRESSED) => opts.compressed = Some(6),
            Some(atoms::DETERMINISTIC) => opts.deterministic = true,
            Some(atoms::LOCAL) => opts.local = true,
            _ => {
                // SAFETY: BIF arguments remain on stable live heaps throughout this call.
                let tuple = unsafe { head.tuple_ref() }.ok_or(BifError::BADARG)?;
                if tuple.len() != 2 {
                    return Err(BifError::BADARG);
                }
                let name = tuple
                    .get(0)
                    .and_then(Term::as_atom)
                    .ok_or(BifError::BADARG)?;
                let value = tuple.get(1).unwrap().as_small().ok_or(BifError::BADARG)?;
                match (name, value) {
                    (atoms::COMPRESSED, 0..=9) => opts.compressed = Some(value as u8),
                    (atoms::MINOR_VERSION, 0..=2) => opts.minor = value as u8,
                    _ => return Err(BifError::BADARG),
                }
            }
        }
    }
    Ok(opts)
}

trait ByteOutput {
    fn len(&self) -> usize;
    fn push(&mut self, byte: u8);
    fn extend_from_slice(&mut self, bytes: &[u8]);
    fn extend_zeroed(&mut self, len: usize);
    fn patch(&mut self, at: usize, bytes: &[u8]);
    fn mask_last(&mut self, mask: u8);
    fn slice(&self, range: std::ops::Range<usize>) -> &[u8];
    fn slice_mut(&mut self, range: std::ops::Range<usize>) -> &mut [u8];
    fn failed(&self) -> bool {
        false
    }

    fn write_bitstring(
        &mut self,
        term: Term,
        start: usize,
        bit_count: usize,
    ) -> Result<(), BifError> {
        let byte_count = bit_count.div_ceil(8);
        let start_at = self.len();
        self.extend_zeroed(byte_count);
        let destination = self.slice_mut(start_at..start_at + byte_count);
        if destination.len() != byte_count {
            return Err(BifError::SystemLimit);
        }
        crate::pure::copy_bitstring_range(term, start, destination, bit_count)
    }
}

impl ByteOutput for Vec<u8> {
    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn push(&mut self, byte: u8) {
        Vec::push(self, byte);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        Vec::extend_from_slice(self, bytes);
    }

    fn extend_zeroed(&mut self, len: usize) {
        self.resize(self.len() + len, 0);
    }

    fn patch(&mut self, at: usize, bytes: &[u8]) {
        self[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn mask_last(&mut self, mask: u8) {
        *self.last_mut().expect("ETF output has a last byte") &= mask;
    }

    fn slice(&self, range: std::ops::Range<usize>) -> &[u8] {
        &self[range]
    }

    fn slice_mut(&mut self, range: std::ops::Range<usize>) -> &mut [u8] {
        &mut self[range]
    }
}

impl<A> ByteOutput for SmallVec<A>
where
    A: smallvec::Array<Item = u8>,
{
    fn len(&self) -> usize {
        SmallVec::len(self)
    }

    fn push(&mut self, byte: u8) {
        SmallVec::push(self, byte);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        SmallVec::extend_from_slice(self, bytes);
    }

    fn extend_zeroed(&mut self, len: usize) {
        self.resize(self.len() + len, 0);
    }

    fn patch(&mut self, at: usize, bytes: &[u8]) {
        self[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn mask_last(&mut self, mask: u8) {
        *self.last_mut().expect("ETF output has a last byte") &= mask;
    }

    fn slice(&self, range: std::ops::Range<usize>) -> &[u8] {
        &self[range]
    }

    fn slice_mut(&mut self, range: std::ops::Range<usize>) -> &mut [u8] {
        &mut self[range]
    }
}

struct OutputSlice<'a> {
    bytes: &'a mut [u8],
    position: usize,
    failed: bool,
}

impl<'a> OutputSlice<'a> {
    fn new(bytes: &'a mut [u8], position: usize) -> Self {
        Self {
            bytes,
            position,
            failed: false,
        }
    }
}

impl ByteOutput for OutputSlice<'_> {
    fn len(&self) -> usize {
        self.position
    }

    fn push(&mut self, byte: u8) {
        self.bytes[self.position] = byte;
        self.position = self.position.saturating_add(1);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let end = self.position.saturating_add(bytes.len());
        self.bytes[self.position..end].copy_from_slice(bytes);
        self.position = end;
    }

    fn extend_zeroed(&mut self, len: usize) {
        let end = self.position.saturating_add(len);
        self.bytes[self.position..end].fill(0);
        self.position = end;
    }

    fn patch(&mut self, at: usize, bytes: &[u8]) {
        self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn mask_last(&mut self, mask: u8) {
        self.bytes[self.position - 1] &= mask;
    }

    fn slice(&self, range: std::ops::Range<usize>) -> &[u8] {
        &self.bytes[range]
    }

    fn slice_mut(&mut self, range: std::ops::Range<usize>) -> &mut [u8] {
        &mut self.bytes[range]
    }

    fn failed(&self) -> bool {
        self.failed
    }

    fn write_bitstring(
        &mut self,
        term: Term,
        start: usize,
        bit_count: usize,
    ) -> Result<(), BifError> {
        // The copy fills every byte of the range, so it needs no zeroed bytes first.
        let end = self.position.saturating_add(bit_count.div_ceil(8));
        let destination = self
            .bytes
            .get_mut(self.position..end)
            .ok_or(BifError::SystemLimit)?;
        crate::pure::copy_bitstring_range(term, start, destination, bit_count)?;
        self.position = end;
        Ok(())
    }
}

fn int_bytes(out: &mut impl ByteOutput, n: &BigInt) {
    if let Some(n) = n.to_i64() {
        if let Ok(byte) = u8::try_from(n) {
            out.extend_from_slice(&[97, byte]);
            return;
        }
        if let Ok(word) = i32::try_from(n) {
            out.push(98);
            out.extend_from_slice(&word.to_be_bytes());
            return;
        }
    }
    let (sign, digits) = n.to_bytes_le();
    if digits.len() < 256 {
        out.extend_from_slice(&[110, digits.len() as u8]);
    } else {
        out.push(111);
        out.extend_from_slice(&(digits.len() as u32).to_be_bytes());
    }
    out.push(u8::from(sign == Sign::Minus));
    out.extend_from_slice(&digits);
}

// Port of erts/emulator/beam/external.c:2877 (enc_atom), OTP-29.1.1.
fn atom_bytes(out: &mut impl ByteOutput, atom: Atom, minor: u8) -> Result<(), BifError> {
    atom_bytes_in(global_atoms(), out, atom, minor)
}

/// `enc_atom` with the atom table already in hand, one record lookup per atom.
#[inline(always)]
fn atom_bytes_in(
    table: &arinsal_term::AtomTable,
    out: &mut impl ByteOutput,
    atom: Atom,
    minor: u8,
) -> Result<(), BifError> {
    let (name, latin1_chars) = table.encoding_info(atom).ok_or(BifError::BADARG)?;
    if minor <= 1
        && let Some(chars) = latin1_chars
    {
        out.extend_from_slice(&[100, (chars >> 8) as u8, chars as u8]);
        if chars == name.len() {
            out.extend_from_slice(name.as_bytes());
        } else {
            for character in name.chars() {
                out.push(character as u8);
            }
        }
        return Ok(());
    }
    let bytes = name.as_bytes();
    if bytes.len() <= 255 {
        out.extend_from_slice(&[119, bytes.len() as u8]);
    } else {
        out.extend_from_slice(&[118, (bytes.len() >> 8) as u8, bytes.len() as u8]);
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn atom_term(out: &mut impl ByteOutput, term: Term, minor: u8) -> Result<(), BifError> {
    atom_bytes(out, term.as_atom().ok_or(BifError::BADARG)?, minor)
}

// Port of erts/emulator/beam/external.c:encode_atom_size, OTP-29.1.1.
#[inline(always)]
fn atom_size_in(table: &arinsal_term::AtomTable, atom: Atom, minor: u8) -> Result<usize, BifError> {
    let (name, latin1_chars) = table.encoding_info(atom).ok_or(BifError::BADARG)?;
    Ok(
        if minor <= 1
            && let Some(chars) = latin1_chars
        {
            3 + chars
        } else if name.len() <= 255 {
            2 + name.len()
        } else {
            3 + name.len()
        },
    )
}

/// Read the local node name and creation the first time a pid, port or reference needs them.
#[inline(always)]
fn resolve_local_node(opts: &mut EncodeOpts, source: Option<fn() -> (Atom, u32)>) {
    if opts.local_node.is_none()
        && let Some(source) = source
    {
        opts.local_node = Some(source());
    }
}

/// One cons of `ENC_ONE_CONS`: returns the head and queues the tail.
// Port of erts/emulator/beam/external.c (encode_one_cons), OTP-29.1.1.
#[inline(always)]
fn encode_one_cons(
    stack: &mut WStack,
    out: &mut impl ByteOutput,
    cons: Term,
) -> Result<Term, BifError> {
    let len_cnt = pop_stack_small(stack)?;
    // SAFETY: the source cons stays live while this BIF is suspended.
    let (head, tail) = unsafe { cons.cons_ref() }.ok_or(BifError::BADARG)?;
    if is_list_term(tail) {
        stack.push(stack_small(len_cnt + 1)?);
        push_term_task(stack, ENC_ONE_CONS, tail);
    } else {
        let len_at = pop_stack_small(stack)?;
        out.patch(
            len_at,
            &u32::try_from(len_cnt)
                .map_err(|_| BifError::SystemLimit)?
                .to_be_bytes(),
        );
        push_term_task(stack, ENC_TERM, tail);
    }
    Ok(head)
}

// Port of erts/emulator/beam/external.c:encode_small_size, OTP-29.1.1.
fn small_size(value: i64) -> usize {
    if (0..256).contains(&value) {
        2
    } else if i32::try_from(value).is_ok() {
        5
    } else {
        let magnitude = value.unsigned_abs();
        big_size((64 - magnitude.leading_zeros() as usize).div_ceil(8))
    }
}

fn big_size(digits: usize) -> usize {
    1 + if digits < 256 { 1 } else { 4 } + 1 + digits
}

fn bignum_size(term: Term) -> Result<usize, BifError> {
    term.with_bignum_digits_mut(|digits| {
        let Some(last) = digits.last() else {
            return 0;
        };
        let significant = (64 - last.leading_zeros() as usize).div_ceil(8);
        (digits.len() - 1) * 8 + significant
    })
    .filter(|size| *size > 0)
    .map(big_size)
    .ok_or(BifError::BADARG)
}

// Port of erts/emulator/beam/external.c:3542 (SMALL_DEF), OTP-29.1.1.
fn write_small(out: &mut impl ByteOutput, n: i64) {
    if (0..256).contains(&n) {
        out.push(97);
        out.push(n as u8);
    } else if let Ok(word) = i32::try_from(n) {
        out.push(98);
        out.extend_from_slice(&word.to_be_bytes());
    } else {
        int_bytes(out, &BigInt::from(n));
    }
}

fn fun_of<'a>(term: Term) -> Result<FunRef<'a>, BifError> {
    // SAFETY: the live source heap retains the fun entry and its environment.
    unsafe { term.fun_ref() }.ok_or(BifError::BADARG)
}

fn record_of<'a>(term: Term) -> Result<arinsal_term::RecordRef<'a>, BifError> {
    // SAFETY: the live record retains its definition and values.
    unsafe { term.record_ref() }.ok_or(BifError::BADARG)
}

/// Leading byte-valued elements of a list and whether the whole list is a string.
// Port of erts/emulator/beam/external.c (is_external_string), OTP-29.1.1.
fn external_string_prefix(mut term: Term) -> (usize, bool) {
    let mut len = 0usize;
    while is_list_term(term) {
        let Ok((head, tail)) = crate::pure::iolist_cons(term) else {
            return (len, false);
        };
        // A small integer in 0..=255: the low four tag bits are 1111 and the value is above.
        if head.word() & 15 != 15 || head.word() >> 4 > 255 {
            return (len, false);
        }
        len += 1;
        if len > 0xffff {
            return (len, false);
        }
        term = tail;
    }
    (len, term == Term::NIL)
}

fn bit_bytes(term: Term) -> Result<(SmallVec<[u8; 64]>, usize), BifError> {
    // SAFETY: the process owns the binary; no writable append occurs in this BIF.
    let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
    let mut bytes = SmallVec::new();
    bytes.resize(view.bit_len().div_ceil(8), 0);
    if view.start_bit().is_multiple_of(8) {
        let start = view.start_bit() / 8;
        let len = bytes.len();
        bytes.copy_from_slice(&view.bytes()[start..start + len]);
    } else {
        for (i, byte) in bytes.iter_mut().enumerate() {
            let at = view.start_bit() + i * 8;
            let first = view.bytes()[at / 8];
            let next = view.bytes().get(at / 8 + 1).copied().unwrap_or(0);
            *byte = (first << (at % 8)) | (next >> (8 - at % 8));
        }
    }
    if view.bit_len() % 8 != 0 {
        let mask = 0xff << (8 - view.bit_len() % 8);
        *bytes.last_mut().unwrap() &= mask;
    }
    Ok((bytes, view.bit_len()))
}

fn exact_key_cmp(left: Term, right: Term) -> Ordering {
    // Port of erts/emulator/beam/external.c:3217 (CMP_TERM), OTP-29.1.1.
    cmp_exact(left, right)
}

const WSTACK_INLINE: usize = 32;

/// The work stack of the encoder passes.
// Port of DECLARE_WSTACK / WSTACK_PUSH / WSTACK_POP in erts/emulator/beam/erl_term.h and
// global.h, OTP-29.1.1: a default-size array that lives in the frame of the pass, a heap
// overflow area, and `WSTACK_SAVE` / `WSTACK_RESTORE` to move the contents into the saved
// context (`EncodeWalk::work`) when the pass yields.
struct WStack {
    len: usize,
    inline: [Term; WSTACK_INLINE],
    spill: Vec<Term>,
}

impl WStack {
    #[inline(always)]
    fn new() -> Self {
        Self {
            len: 0,
            inline: [Term::NON_VALUE; WSTACK_INLINE],
            spill: Vec::new(),
        }
    }

    /// `WSTACK_RESTORE`: take the words of a saved context.
    #[inline(always)]
    fn restore(&mut self, saved: &mut Vec<Term>) {
        if !saved.is_empty() {
            for term in saved.drain(..) {
                self.push(term);
            }
        }
    }

    #[inline(always)]
    fn push(&mut self, term: Term) {
        if self.len < WSTACK_INLINE {
            self.inline[self.len] = term;
        } else {
            self.push_spilled(term);
        }
        self.len += 1;
    }

    // `WSTACK_EXPAND`: the overflow area grows by doubling from a first block.
    #[cold]
    #[inline(never)]
    fn push_spilled(&mut self, term: Term) {
        if self.spill.capacity() == 0 {
            self.spill.reserve(256);
        }
        self.spill.push(term);
    }

    #[inline(always)]
    fn pop(&mut self) -> Option<Term> {
        if self.len == 0 {
            return None;
        }
        self.len -= 1;
        if self.len < WSTACK_INLINE {
            Some(self.inline[self.len])
        } else {
            self.spill.pop()
        }
    }

    #[inline(always)]
    fn last(&self) -> Option<Term> {
        match self.len {
            0 => None,
            len if len <= WSTACK_INLINE => Some(self.inline[len - 1]),
            _ => self.spill.last().copied(),
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `WSTACK_SAVE`: move the contents, bottom first, into `saved`.
    fn save(&mut self, saved: &mut Vec<Term>) {
        if self.len == 0 {
            return;
        }
        saved.clear();
        saved.extend_from_slice(&self.inline[..self.len.min(WSTACK_INLINE)]);
        saved.append(&mut self.spill);
        self.len = 0;
    }
}

// Size pass stack words. Port of LIST_TAIL_OP, HASHMAP_NODE_OP and TERM_ARRAY_OP(N) in
// erts/emulator/beam/external.c (encode_size_struct_int), OTP-29.1.1: erts tells them from
// terms because they are header-tagged; a `catch` immediate never occurs in a live term and
// plays that role here, so plain terms are pushed as one word like `WSTACK_FAST_PUSH(s, node)`.
const SIZE_LIST_TAIL: u64 = 0;
const SIZE_HASHMAP_NODE: u64 = 1;
const SIZE_ARRAY: u64 = 2;

// Array kinds of TERM_ARRAY_OP: erts stores `Eterm*` plus the element count; here the
// container term replaces the pointer and the kind says how to index into it.
const ARRAY_TUPLE: u64 = 0;
const ARRAY_FLAT_KEYS: u64 = 1;
const ARRAY_FLAT_VALUES: u64 = 2;
const ARRAY_FUN_ENV: u64 = 3;
const ARRAY_RECORD: u64 = 4;

const fn size_op(code: u64) -> Term {
    Term::catch(code)
}

// Encode pass commands are small-integer terms below the term entry they belong to
// (`WSTACK_PUSH2(s, obj, ENC_...)`). Codes from ENC_ARRAY up are
// ENC_LAST_ARRAY_ELEMENT+N (tuple elements) and ENC_MAP_PAIR with the pairs left.
const ENC_TERM_CODE: u64 = 0;
const ENC_ONE_CONS_CODE: u64 = 1;
const ENC_PATCH_FUN_SIZE_CODE: u64 = 2;
const ENC_BIN_COPY_CODE: u64 = 3;
const ENC_HASHMAP_NODE_CODE: u64 = 5;
const ENC_START_SORTING_MAP_CODE: u64 = 7;
const ENC_ARRAY: u64 = 16;
const ENC_PAIR_KIND: u64 = 1;

const ENC_TERM: Term = stack_command(ENC_TERM_CODE as i64);
const ENC_ONE_CONS: Term = stack_command(ENC_ONE_CONS_CODE as i64);
const ENC_PATCH_FUN_SIZE: Term = stack_command(ENC_PATCH_FUN_SIZE_CODE as i64);
const ENC_BIN_COPY: Term = stack_command(ENC_BIN_COPY_CODE as i64);
const ENC_HASHMAP_NODE: Term = stack_command(ENC_HASHMAP_NODE_CODE as i64);
const ENC_START_SORTING_MAP: Term = stack_command(ENC_START_SORTING_MAP_CODE as i64);

const fn stack_command(code: i64) -> Term {
    match Term::small(code) {
        Some(term) => term,
        None => panic!("ETF stack command must fit a small integer"),
    }
}

#[inline(always)]
fn is_list_term(term: Term) -> bool {
    term.word() & 3 == 1
}

// Port of WSTACK_PUSH2 in erts/emulator/beam/external.c, OTP-29.1.1.
#[inline(always)]
fn push_term_task(stack: &mut WStack, command: Term, term: Term) {
    stack.push(term);
    stack.push(command);
}

// Port of the `WSTACK_PUSH` calls that push a node without an operation word.
#[inline(always)]
fn push_task(stack: &mut WStack, command: Option<Term>, term: Term) {
    stack.push(term);
    if let Some(command) = command {
        stack.push(command);
    }
}

#[inline(always)]
fn stack_small(value: usize) -> Result<Term, BifError> {
    Term::small(i64::try_from(value).map_err(|_| BifError::SystemLimit)?)
        .ok_or(BifError::SystemLimit)
}

#[inline(always)]
fn pop_stack_small(stack: &mut WStack) -> Result<usize, BifError> {
    usize::try_from(
        stack
            .pop()
            .and_then(Term::as_small)
            .ok_or(BifError::BADARG)?,
    )
    .map_err(|_| BifError::BADARG)
}

// Port of TERM_ARRAY_OP(N) pushes in erts/emulator/beam/external.c
// (encode_size_struct_int), OTP-29.1.1: `remaining` elements still to read.
#[inline(always)]
fn push_size_array(stack: &mut WStack, container: Term, remaining: usize, kind: u64) {
    stack.push(container);
    stack.push(size_op(SIZE_ARRAY + (((remaining as u64) << 3) | kind)));
}

/// Element `len - remaining` of the array a TERM_ARRAY_OP walks.
#[inline(always)]
fn size_array_element(kind: u64, container: Term, remaining: usize) -> Result<Term, BifError> {
    match kind {
        ARRAY_TUPLE => crate::pure::tuple_element_from_end(container, remaining),
        ARRAY_FLAT_KEYS | ARRAY_FLAT_VALUES => {
            let (key, value) = flatmap_pair(container, remaining)?;
            Ok(if kind == ARRAY_FLAT_KEYS { key } else { value })
        }
        ARRAY_FUN_ENV => {
            let fun = fun_of(container)?;
            let index = fun
                .num_free()
                .checked_sub(remaining)
                .ok_or(BifError::BADARG)?;
            fun.free(index).ok_or(BifError::BADARG)
        }
        _ => {
            let record = record_of(container)?;
            let index = record
                .len()
                .checked_sub(remaining)
                .ok_or(BifError::BADARG)?;
            record.value(index).ok_or(BifError::BADARG)
        }
    }
}

/// Key and value of a flatmap with `remaining` pairs still to read.
#[inline(always)]
fn flatmap_pair(map: Term, remaining: usize) -> Result<(Term, Term), BifError> {
    let checked = arinsal_maps::checked_map(map).map_err(|_| BifError::BADARG)?;
    let arinsal_maps::CheckedMapKind::Flatmap(flat) = checked.kind() else {
        return Err(BifError::BADARG);
    };
    flat.pair_at(flat.size().checked_sub(remaining).ok_or(BifError::BADARG)?)
        .ok_or(BifError::BADARG)
}

/// Pop the next object of the size pass, resolving the operation words.
// Port of the pop section of erts/emulator/beam/external.c (encode_size_struct_int),
// OTP-29.1.1.
#[inline(always)]
fn size_pop(stack: &mut WStack) -> Result<Option<Term>, BifError> {
    let Some(word) = stack.pop() else {
        return Ok(None);
    };
    if word.word() & 63 != 0x1b {
        return Ok(Some(word));
    }
    let code = word.word() >> 6;
    if code == SIZE_LIST_TAIL {
        let tail = stack.pop().ok_or(BifError::BADARG)?;
        if is_list_term(tail) {
            let (head, rest) = crate::pure::iolist_cons(tail)?;
            push_term_task(stack, size_op(SIZE_LIST_TAIL), rest);
            Ok(Some(head))
        } else {
            Ok(Some(tail))
        }
    } else if code == SIZE_HASHMAP_NODE {
        let node = stack.pop().ok_or(BifError::BADARG)?;
        Ok(Some(push_hashmap_node_tasks(
            stack,
            node,
            Some(size_op(SIZE_HASHMAP_NODE)),
            None,
        )?))
    } else {
        let spec = code - SIZE_ARRAY;
        let remaining = (spec >> 3) as usize;
        let container = stack.pop().ok_or(BifError::BADARG)?;
        let obj = size_array_element(spec & 7, container, remaining)?;
        if remaining > 1 {
            push_term_task(stack, size_op(code - 8), container);
        }
        Ok(Some(obj))
    }
}

// Port of erts/emulator/beam/external.c:5812-5825 (HASHMAP_NODE_OP), OTP-29.1.1.
#[inline(always)]
fn push_hashmap_root_tasks(
    stack: &mut WStack,
    map: Term,
    node_command: Term,
    term_command: Option<Term>,
) -> Result<(), BifError> {
    let children = arinsal_term::MapNodeChildren::new(map).ok_or(BifError::BADARG)?;
    for child in children.rev() {
        let command = if matches!(child.classify(), TermKind::List | TermKind::Tuple) {
            Some(node_command)
        } else {
            term_command
        };
        push_task(stack, command, child);
    }
    Ok(())
}

// Port of erts/emulator/beam/external.c:3404-3419 (ENC_HASHMAP_NODE), OTP-29.1.1.
#[inline(always)]
fn push_hashmap_node_tasks(
    stack: &mut WStack,
    node: Term,
    node_command: Option<Term>,
    value_command: Option<Term>,
) -> Result<Term, BifError> {
    if node.classify() == TermKind::List {
        let (key, value) = arinsal_term::hashmap_leaf_pair(node).ok_or(BifError::BADARG)?;
        push_task(stack, value_command, value);
        return Ok(key);
    }
    let children = arinsal_term::MapNodeChildren::new(node).ok_or(BifError::BADARG)?;
    let mut children = children;
    let last = children.next().ok_or(BifError::BADARG)?;
    for child in children.rev() {
        push_task(stack, node_command, child);
    }
    let (key, value) = arinsal_term::hashmap_leaf_pair(last).ok_or(BifError::BADARG)?;
    push_task(stack, value_command, value);
    Ok(key)
}

#[inline(always)]
fn push_sorted_map_tasks(stack: &mut WStack, pairs: Vec<(Term, Term)>) {
    // Port of erts/emulator/beam/external.c:3491-3510 (ENC_PUSH_SORTED_MAP), OTP-29.1.1.
    for (key, value) in pairs.into_iter().rev() {
        push_term_task(stack, ENC_TERM, value);
        push_term_task(stack, ENC_TERM, key);
    }
}

struct MapSort {
    source: Vec<(Term, Term)>,
    destination: Vec<(Term, Term)>,
    width: usize,
    start: usize,
    left: usize,
    middle: usize,
    right: usize,
    output: usize,
}

impl MapSort {
    fn new(source: Vec<(Term, Term)>) -> Self {
        let len = source.len();
        Self {
            source,
            destination: vec![(Term::NIL, Term::NIL); len],
            width: 1,
            start: 0,
            left: 0,
            middle: 0,
            right: 0,
            output: 0,
        }
    }

    fn step(&mut self, budget: usize) -> usize {
        let len = self.source.len();
        let mut consumed = 0;
        while consumed < budget && self.width < len {
            if self.start >= len {
                std::mem::swap(&mut self.source, &mut self.destination);
                self.width = self.width.saturating_mul(2);
                self.start = 0;
                self.left = 0;
                self.middle = 0;
                self.right = 0;
                self.output = 0;
                continue;
            }
            if self.middle == self.start && self.output == self.start {
                self.middle = self.start.saturating_add(self.width).min(len);
                self.right = self
                    .start
                    .saturating_add(self.width.saturating_mul(2))
                    .min(len);
                self.left = self.start;
                self.output = self.start;
            }
            if self.output == self.right {
                self.start = self.right;
                self.middle = self.start;
                continue;
            }
            let right_index = self.middle + self.output - self.left;
            let take_left = self.left < self.middle
                && (right_index >= self.right
                    || exact_key_cmp(self.source[self.left].0, self.source[right_index].0)
                        != Ordering::Greater);
            let selected = if take_left {
                let pair = self.source[self.left];
                self.left += 1;
                pair
            } else {
                self.source[right_index]
            };
            self.destination[self.output] = selected;
            self.output += 1;
            consumed += 1;
        }
        consumed
    }

    fn is_done(&self) -> bool {
        self.width >= self.source.len()
    }

    fn finish(self) -> Vec<(Term, Term)> {
        self.source
    }
}

/// The body of `encode_size_struct_int`: `Ok(None)` when the pass finished, `Ok(Some(obj))`
/// when the reduction budget ran out with `obj` still to be sized.
#[inline(always)]
fn size_walk(
    opts: &mut EncodeOpts,
    node_source: Option<fn() -> (Atom, u32)>,
    stack: &mut WStack,
    pending: Option<Term>,
    result: &mut usize,
    consumed: &mut usize,
    budget: usize,
) -> Result<Option<Term>, BifError> {
    let table = global_atoms();
    let minor = opts.minor;
    let mut total = *result;
    let mut work = *consumed;
    let mut obj = match pending {
        Some(obj) => obj,
        None => match size_pop(stack)? {
            Some(obj) => obj,
            None => return Ok(None),
        },
    };
    macro_rules! add {
        ($size:expr) => {
            total = total.checked_add($size).ok_or(BifError::SystemLimit)?
        };
    }
    loop {
        // `if (ctx && --r <= 0)` of erts: yield before sizing `obj`.
        if work + 1 >= budget {
            *result = total;
            *consumed = work;
            return Ok(Some(obj));
        }
        work += 1;
        match obj.classify() {
            TermKind::Number => {
                if let Some(value) = obj.as_small() {
                    add!(small_size(value));
                } else if obj.header().is_some_and(|header| header & 63 == 0x18) {
                    add!(if minor == 0 { 32 } else { 9 });
                } else {
                    add!(bignum_size(obj)?);
                }
            }
            TermKind::Atom => add!(atom_size_in(
                table,
                obj.as_atom().ok_or(BifError::BADARG)?,
                minor
            )?),
            TermKind::Nil => add!(1),
            TermKind::List => {
                // Port of erts/emulator/beam/external.c (is_external_string), OTP-29.1.1:
                // one scan returns both the string length and the work count.
                let (len, is_string) = external_string_prefix(obj);
                work += len / 2;
                if is_string {
                    add!(3 + len);
                } else {
                    add!(5);
                    let (head, rest) = crate::pure::iolist_cons(obj)?;
                    push_term_task(stack, size_op(SIZE_LIST_TAIL), rest);
                    obj = head;
                    continue;
                }
            }
            TermKind::Tuple => {
                let arity = crate::pure::tuple_arity(obj)?;
                add!(if arity <= 255 { 2 } else { 5 });
                if arity > 0 {
                    if arity > 1 {
                        push_size_array(stack, obj, arity - 1, ARRAY_TUPLE);
                    }
                    obj = crate::pure::tuple_element(obj, 0)?;
                    continue;
                }
            }
            TermKind::Map => {
                let checked = arinsal_maps::checked_map(obj).map_err(|_| BifError::BADARG)?;
                match checked.kind() {
                    arinsal_maps::CheckedMapKind::Flatmap(_) => {
                        let size = checked.size();
                        add!(5);
                        if size > 0 {
                            push_size_array(stack, obj, size, ARRAY_FLAT_VALUES);
                            push_size_array(stack, obj, size, ARRAY_FLAT_KEYS);
                        }
                    }
                    arinsal_maps::CheckedMapKind::Hashmap(_) => {
                        let children =
                            arinsal_term::MapNodeChildren::new(obj).ok_or(BifError::BADARG)?;
                        if children.is_head() {
                            add!(5);
                        }
                        push_hashmap_root_tasks(stack, obj, size_op(SIZE_HASHMAP_NODE), None)?;
                    }
                }
            }
            TermKind::Bitstring => {
                let bits = crate::pure::bitstring_bit_len(obj)?;
                let len = bits.div_ceil(8);
                let header: usize = if bits.is_multiple_of(8) { 5 } else { 6 };
                add!(header.checked_add(len).ok_or(BifError::SystemLimit)?);
            }
            TermKind::Pid | TermKind::Port | TermKind::Ref => {
                // Port of erts/emulator/beam/external.c:5613-5636 (REF_DEF sizing), OTP-29.1.1.
                resolve_local_node(opts, node_source);
                let identity = obj.identity().ok_or(BifError::BADARG)?;
                let identity = local_identity(identity, opts.local_node);
                let node_size = if opts.local {
                    1
                } else {
                    atom_size_in(
                        table,
                        match identity {
                            Identity::Pid { node, .. }
                            | Identity::Port { node, .. }
                            | Identity::Ref { node, .. } => node,
                        },
                        minor,
                    )?
                };
                let size = match identity {
                    Identity::Pid { .. } => 1 + node_size + 12,
                    Identity::Port { .. } => 1 + node_size + 12,
                    Identity::Ref { ids, .. } => 1 + 2 + node_size + 4 + 4 * ids.len(),
                };
                add!(size);
            }
            TermKind::Fun => {
                let fun = fun_of(obj)?;
                match &fun {
                    FunRef::Export { entry } => {
                        add!(
                            1 + atom_size_in(table, entry.module, minor)?
                                + atom_size_in(table, entry.function, minor)?
                                + small_size(i64::from(entry.arity))
                        );
                    }
                    FunRef::Local { entry, .. } => {
                        add!(
                            1 + 4
                                + 1
                                + 16
                                + 4
                                + 4
                                + atom_size_in(table, entry.module, minor)?
                                + small_size(i64::from(entry.old_index))
                                + small_size(i64::from(entry.old_uniq))
                        );
                        stack.push(entry.pid);
                        let free = fun.num_free();
                        if free > 1 {
                            push_size_array(stack, obj, free - 1, ARRAY_FUN_ENV);
                        }
                        if free != 0 {
                            obj = fun.free(0).ok_or(BifError::BADARG)?;
                            continue;
                        }
                    }
                }
            }
            TermKind::Record => {
                let record = record_of(obj)?;
                let mut size = 1
                    + 4
                    + 1
                    + atom_size_in(table, record.module(), minor)?
                    + atom_size_in(table, record.name(), minor)?;
                for index in 0..record.len() {
                    let sorted = record.sorted_index(index).ok_or(BifError::BADARG)?;
                    size = size
                        .checked_add(atom_size_in(
                            table,
                            record.key(sorted).ok_or(BifError::BADARG)?,
                            minor,
                        )?)
                        .ok_or(BifError::SystemLimit)?;
                }
                add!(size);
                let values = record.len();
                if values > 1 {
                    push_size_array(stack, obj, values - 1, ARRAY_RECORD);
                }
                if values != 0 {
                    obj = record.value(0).ok_or(BifError::BADARG)?;
                    continue;
                }
            }
            _ => return Err(BifError::Unsupported("ETF representation")),
        }
        match size_pop(stack)? {
            Some(next) => obj = next,
            None => {
                *result = total;
                *consumed = work;
                return Ok(None);
            }
        }
    }
}

type EncodedWithSplits = (Vec<u8>, Vec<(usize, usize)>);

/// Build the heap term of a refc binary that holds a finished encoding of `size` bytes.
pub fn install_refc_binary<H: HeapAlloc>(
    heap: &mut H,
    binary: RefcBinary,
    size: usize,
) -> Result<Term, BifError> {
    let mut heap = Heap(heap);
    TermBuilder::new(&mut heap)
        .refc_binary(binary, size * 8)
        .map_err(|_| BifError::SystemLimit)
}

/// Result of [`EncodeWalk::encode_into_refc`].
pub enum RefcEncoded {
    /// The finished binary term.
    Done(Term),
    /// The reduction budget ran out; the binary holds the bytes written so far.
    Partial(RefcBinary),
}

/// Incremental ETF encoder used by the VM's trapping `term_to_binary` path.
pub struct EncodeWalk {
    opts: EncodeOpts,
    /// The saved work stack of whichever pass is running (`ctx->wstack`).
    work: Vec<Term>,
    current_term: Option<Term>,
    size_current: Option<Term>,
    encoded_size: usize,
    written: usize,
    direct_started: bool,
    sized: bool,
    free_first: bool,
    iovec: bool,
    /// State that the plain `term_to_binary` path never touches, out of line so that the
    /// walk stays small enough to be moved without a call to `memcpy`.
    cold: Option<Box<EncodeCold>>,
    /// Whether to record the boundaries of large binaries for `term_to_iovec`.
    record_splits: bool,
    /// Where to read the node name and creation when the first pid, port or reference needs
    /// them; erts reads `erts_this_node` only when `enc_internal_pid` runs.
    node_source: Option<fn() -> (Atom, u32)>,
}

/// The rarely used parts of an [`EncodeWalk`]: the owned output buffer of `step`, the iovec
/// split points, the deterministic map sort, the local-hash walk and the zlib stream.
#[derive(Default)]
struct EncodeCold {
    out: Vec<u8>,
    splits: Vec<(usize, usize)>,
    map_sort: Option<Box<MapSort>>,
    local_hash: Option<BlockHashWalk>,
    compressor: Option<Compress>,
    compression_finished: bool,
}

impl EncodeWalk {
    fn cold(&mut self) -> &mut EncodeCold {
        self.cold.get_or_insert_with(Default::default)
    }

    /// Empty state used after the source term has been fully encoded.
    pub fn completed() -> Self {
        Self {
            opts: EncodeOpts::default(),
            work: Vec::new(),
            current_term: None,
            size_current: None,
            encoded_size: 0,
            written: 0,
            direct_started: false,
            sized: true,
            free_first: false,
            iovec: false,
            cold: None,
            record_splits: false,
            node_source: None,
        }
    }

    /// Begin encoding a `term_to_binary/1,2` argument vector.
    #[inline]
    pub fn new(args: &[Term]) -> Result<Self, BifError> {
        let opts = options(args.get(1).copied())?;
        Ok(Self::start(args[0], opts))
    }

    /// Begin a size-only walk for `external_size/1,2`, where compression is ignored.
    pub fn new_external_size(args: &[Term]) -> Result<Self, BifError> {
        let mut opts = options(args.get(1).copied())?;
        opts.compressed = None;
        Ok(Self::start(args[0], opts))
    }

    /// Use the running node identity when encoding locally tagged pids, ports, and refs.
    pub fn set_local_node(&mut self, node: arinsal_term::Atom, creation: u32) {
        self.opts.local_node = Some((node, creation));
    }

    /// Like [`Self::set_local_node`], but `source` runs only if the term holds a pid, port or
    /// reference.
    pub fn set_local_node_source(&mut self, source: fn() -> (Atom, u32)) {
        self.node_source = Some(source);
    }

    #[inline(always)]
    fn start(term: Term, opts: EncodeOpts) -> Self {
        let mut encoded_size = 1;
        if opts.local {
            // Port of erts/emulator/beam/external.c:3305 (encode LOCAL_EXT), OTP-29.1.1.
            encoded_size += 5;
        }
        Self {
            opts,
            work: Vec::new(),
            current_term: Some(term),
            size_current: Some(term),
            encoded_size,
            written: 0,
            direct_started: false,
            sized: false,
            free_first: true,
            iovec: false,
            cold: None,
            record_splits: false,
            node_source: None,
        }
    }

    /// Mark the walk as `term_to_iovec`, which references large aligned binaries in place.
    pub fn set_iovec(&mut self, iovec: bool) {
        self.iovec = iovec;
        self.record_splits = iovec;
    }

    /// Exact serialized size after the `encode_size_struct_int` pass.
    pub fn encoded_size(&self) -> Option<usize> {
        self.sized.then_some(self.encoded_size)
    }

    /// Whether zlib compression is active for this encoder.
    pub fn uses_compression(&self) -> bool {
        self.opts.compressed.is_some_and(|level| level > 0)
    }

    /// Whether `erts_term_to_binary_simple` finishes the call: an encoding that fits an
    /// on-heap binary and is not an iovec.
    // Port of erts/emulator/beam/external.c (TTBSize, simple path), OTP-29.1.1.
    pub fn finishes_simple(&self) -> bool {
        let plain = self.opts.compressed.is_none_or(|level| level == 0);
        !(self.iovec && plain) && self.encoded_size <= 64
    }

    /// Count the yield counts of the size pass, at most `budget - 1` of them.
    // Port of erts/emulator/beam/external.c:5579 (encode_size_struct_int), OTP-29.1.1.
    fn size_step(&mut self, budget: usize, consumed: &mut usize) -> Result<bool, BifError> {
        let mut opts = self.opts;
        let node_source = self.node_source;
        let mut stack = WStack::new();
        stack.restore(&mut self.work);
        let mut result = self.encoded_size;
        let mut work = *consumed;
        let pending = self.size_current.take();
        let outcome = size_walk(
            &mut opts,
            node_source,
            &mut stack,
            pending,
            &mut result,
            &mut work,
            budget,
        );
        self.opts = opts;
        stack.save(&mut self.work);
        self.encoded_size = result;
        *consumed = work;
        match outcome? {
            None => Ok(true),
            Some(obj) => {
                self.size_current = Some(obj);
                Ok(false)
            }
        }
    }

    /// Advance the exact size pass used before result allocation.
    pub fn step_size(&mut self, budget: usize) -> Result<(bool, usize), BifError> {
        if self.sized {
            return Ok((true, 0));
        }
        let mut consumed = 0;
        let done = self.size_step(budget, &mut consumed)?;
        if done {
            self.sized = true;
        }
        Ok((done, consumed))
    }

    /// Encode at most `budget` pending terms and patch records into the owned byte buffer.
    pub fn step(&mut self, budget: usize) -> Result<(bool, usize), BifError> {
        let mut output = std::mem::take(&mut self.cold().out);
        if output.is_empty() {
            output.push(131);
            if self.opts.local {
                output.extend_from_slice(&[121, 0, 0, 0, 0]);
            }
        }
        let result = self.step_with_output(budget, &mut output, 0);
        self.cold().out = output;
        result
    }

    /// Encode into the already allocated final binary, retaining the cursor across traps.
    pub fn step_into(
        &mut self,
        output: &mut [u8],
        budget: usize,
    ) -> Result<(bool, usize), BifError> {
        let (sized, size_work) = self.step_size(budget)?;
        if !sized {
            return Ok((false, budget));
        }
        if output.len() != self.encoded_size {
            return Err(BifError::SystemLimit);
        }
        if !self.direct_started {
            let mut writer = OutputSlice::new(output, 0);
            writer.push(131);
            if self.opts.local {
                writer.extend_from_slice(&[121, 0, 0, 0, 0]);
            }
            if writer.failed() {
                return Err(BifError::SystemLimit);
            }
            self.written = writer.len();
            self.direct_started = true;
            if let Some(cold) = self.cold.as_mut() {
                cold.out.clear();
            }
        }
        let mut writer = OutputSlice::new(output, self.written);
        let (mut done, used) = self.step_with_output(budget, &mut writer, size_work)?;
        self.written = writer.len();
        if writer.failed() {
            return Err(BifError::SystemLimit);
        }
        if done && self.opts.local {
            let written = self.written;
            let hash_walk = self
                .cold()
                .local_hash
                .get_or_insert_with(|| BlockHashWalk::new(written - 6, local_node_hash()));
            let remaining_work = budget.saturating_sub(used);
            let hash_budget = (remaining_work / 32).saturating_mul(128);
            let (hash_done, hash_work) = hash_walk.step(writer.slice(6..written), hash_budget);
            let consumed = (hash_work / 128).saturating_mul(32);
            if hash_done {
                let hash = hash_walk.hash.ok_or(BifError::SystemLimit)?;
                writer.patch(2, &hash.to_be_bytes());
            } else {
                done = false;
            }
            let used = used.saturating_add(consumed);
            if writer.failed() {
                return Err(BifError::SystemLimit);
            }
            return Ok((done, used));
        }
        if writer.failed() {
            return Err(BifError::SystemLimit);
        }
        Ok((done, used))
    }

    /// Encode into a fresh refc binary of the sized length, as `erts_term_to_binary_int` fills
    /// `erts_bin_nrml_alloc(size)` before the ProcBin is built. Returns the finished term, or
    /// the partly filled binary if the budget ran out.
    // Port of erts/emulator/beam/external.c:2519-2582 (erts_term_to_binary_int), OTP-29.1.1.
    pub fn encode_into_refc<H: HeapAlloc>(
        &mut self,
        heap: &mut H,
        budget: usize,
    ) -> Result<(RefcEncoded, usize), BifError> {
        let size = self.encoded_size().ok_or(BifError::SystemLimit)?;
        let mut binary = RefcBinary::new_zeroed(size).map_err(|_| BifError::SystemLimit)?;
        let (done, work) = self.step_into(
            binary.bytes_mut_unique().ok_or(BifError::SystemLimit)?,
            budget,
        )?;
        if !done {
            return Ok((RefcEncoded::Partial(binary), work));
        }
        let term = install_refc_binary(heap, binary, size)?;
        Ok((RefcEncoded::Done(term), work))
    }

    /// Encode a simple result directly into its final binary, using erts' stack buffer only
    /// for the compression source on the compressed simple path.
    // Port of erts/emulator/beam/external.c:2250-2319 (`erts_term_to_binary_simple`), OTP-29.1.1.
    pub fn encode_simple_binary<H: HeapAlloc>(&mut self, heap: &mut H) -> Result<Term, BifError> {
        let size = self.encoded_size().ok_or(BifError::SystemLimit)?;
        if size > 64 || !self.finishes_simple() {
            return Err(BifError::BADARG);
        }
        let mut heap = Heap(heap);
        let mut builder = TermBuilder::new(&mut heap);
        if let Some(level) = self.opts.compressed.filter(|level| *level > 0) {
            let mut plain = [0; 64];
            let (done, _) = self.step_into(&mut plain[..size], usize::MAX)?;
            if !done {
                return Err(BifError::SystemLimit);
            }
            let result = builder.binary_from_fn_with_len(size, |destination| {
                if size >= 6 {
                    let mut compressor = Compress::new(Compression::new(level as u32), true);
                    let status = compressor
                        .compress(
                            &plain[1..size],
                            &mut destination[6..],
                            FlushCompress::Finish,
                        )
                        .map_err(|_| arinsal_term::TermError::SystemLimit)?;
                    let compressed_len = usize::try_from(compressor.total_out())
                        .map_err(|_| arinsal_term::TermError::SystemLimit)?;
                    if status == Status::StreamEnd && compressed_len + 6 <= size {
                        destination[0] = 131;
                        destination[1] = 80;
                        destination[2..6].copy_from_slice(&((size - 1) as u32).to_be_bytes());
                        return Ok(compressed_len + 6);
                    }
                }
                destination[..size].copy_from_slice(&plain[..size]);
                Ok(size)
            });
            return result.map_err(|_| BifError::SystemLimit);
        }
        let mut encode_error = None;
        let result = builder.binary_from_fn(size, |destination| {
            match self.step_into(destination, usize::MAX) {
                Ok((true, _)) => {}
                Ok((false, _)) => encode_error = Some(BifError::SystemLimit),
                Err(error) => encode_error = Some(error),
            }
        });
        if let Some(error) = encode_error {
            return Err(error);
        }
        result.map_err(|_| BifError::SystemLimit)
    }

    /// Continue the zlib stream directly into the destination's reserved byte range.
    // Port of erts/emulator/beam/external.c:2750-2807 (TTBCompress), OTP-29.1.1.
    pub fn compress_into(
        &mut self,
        input: &[u8],
        output: &mut [u8],
        budget: usize,
    ) -> Result<(bool, usize), BifError> {
        let level = self
            .opts
            .compressed
            .filter(|level| *level > 0)
            .ok_or(BifError::BADARG)?;
        let cold = self.cold();
        let compressor = cold
            .compressor
            .get_or_insert_with(|| Compress::new(Compression::new(level as u32), true));
        let input_at = usize::try_from(compressor.total_in()).map_err(|_| BifError::SystemLimit)?;
        let output_at =
            usize::try_from(compressor.total_out()).map_err(|_| BifError::SystemLimit)?;
        if input_at > input.len() || output_at > output.len() {
            return Err(BifError::SystemLimit);
        }
        if output_at == output.len() {
            return Ok((cold.compression_finished, 0));
        }
        let end = output_at.saturating_add(budget.max(1)).min(output.len());
        let before = compressor.total_out();
        let status = compressor
            .compress(
                &input[input_at..],
                &mut output[output_at..end],
                FlushCompress::Finish,
            )
            .map_err(|_| BifError::SystemLimit)?;
        let written =
            usize::try_from(compressor.total_out() - before).map_err(|_| BifError::SystemLimit)?;
        cold.compression_finished = status == Status::StreamEnd;
        Ok((cold.compression_finished, written))
    }

    /// Whether the compressed stream fits the size of its plain ETF binary.
    pub fn compression_is_useful(&self) -> bool {
        self.cold.as_ref().is_some_and(|cold| {
            cold.compression_finished
                && cold.compressor.as_ref().is_some_and(|compressor| {
                    compressor.total_out().saturating_add(6) <= self.encoded_size as u64
                })
        })
    }

    /// Whether the zlib stream reached its final block.
    pub fn compression_finished(&self) -> bool {
        self.cold
            .as_ref()
            .is_some_and(|cold| cold.compression_finished)
    }

    /// Number of compressed payload bytes emitted so far.
    pub fn compressed_payload_len(&self) -> Option<usize> {
        self.cold
            .as_ref()
            .and_then(|cold| cold.compressor.as_ref())
            .and_then(|compressor| usize::try_from(compressor.total_out()).ok())
    }

    /// Whether the destination has no remaining compressed payload capacity.
    pub fn compression_output_full(&self) -> bool {
        self.cold
            .as_ref()
            .and_then(|cold| cold.compressor.as_ref())
            .is_some_and(|compressor| {
                compressor.total_out() >= self.encoded_size.saturating_sub(6) as u64
            })
    }

    // Port of erts/emulator/beam/external.c:3253 (enc_term_int), OTP-29.1.1.
    fn step_with_output(
        &mut self,
        budget: usize,
        out: &mut impl ByteOutput,
        mut consumed: usize,
    ) -> Result<(bool, usize), BifError> {
        if !self.sized {
            let (done, size_work) = self.step_size(budget)?;
            consumed += size_work;
            if !done {
                return Ok((false, budget));
            }
        }
        let mut opts = self.opts;
        let node_source = self.node_source;
        let record_splits = self.record_splits;
        let iovec = self.iovec;
        let table = global_atoms();
        // The stack and the pending object live in locals so that the output writes cannot
        // alias them; erts keeps them in registers (`DECLARE_WSTACK`, `obj`).
        let mut stack = WStack::new();
        stack.restore(&mut self.work);
        let mut cur = self.current_term.take();
        let mut free_first = self.free_first;
        loop {
            if consumed + 1 >= budget
                && !(free_first
                    && (cur.is_some()
                        || stack.last().is_some_and(|command| {
                            let code = command.word() >> 4;
                            code == ENC_TERM_CODE
                                || code == ENC_ONE_CONS_CODE
                                || code == ENC_HASHMAP_NODE_CODE
                                || code >= ENC_ARRAY
                        })))
            {
                break;
            }
            let term = if let Some(term) = cur.take() {
                term
            } else {
                // outer_loop
                let Some(command) = stack.pop() else {
                    break;
                };
                let code = command.word() >> 4;
                if code == ENC_TERM_CODE {
                    stack.pop().ok_or(BifError::BADARG)?
                } else if code == ENC_ONE_CONS_CODE {
                    let list = stack.pop().ok_or(BifError::BADARG)?;
                    encode_one_cons(&mut stack, out, list)?
                } else if code >= ENC_ARRAY {
                    let spec = code - ENC_ARRAY;
                    let remaining = (spec >> 3) as usize;
                    let container = stack.pop().ok_or(BifError::BADARG)?;
                    if spec & 7 == ENC_PAIR_KIND {
                        // ENC_MAP_PAIR: one key/value pair of a flatmap.
                        let (key, value) = flatmap_pair(container, remaining)?;
                        if remaining > 1 {
                            push_term_task(&mut stack, stack_command(code as i64 - 8), container);
                        }
                        push_term_task(&mut stack, ENC_TERM, value);
                        key
                    } else {
                        // ENC_LAST_ARRAY_ELEMENT+N: the next tuple element.
                        let element = crate::pure::tuple_element_from_end(container, remaining)?;
                        if remaining > 1 {
                            push_term_task(&mut stack, stack_command(code as i64 - 8), container);
                        }
                        element
                    }
                } else if code == ENC_PATCH_FUN_SIZE_CODE {
                    consumed += 1;
                    let at = pop_stack_small(&mut stack)?;
                    let size = u32::try_from(out.len() - at).map_err(|_| BifError::SystemLimit)?;
                    out.patch(at, &size.to_be_bytes());
                    continue;
                } else if code == ENC_BIN_COPY_CODE {
                    let term = stack.pop().ok_or(BifError::BADARG)?;
                    let bits = pop_stack_small(&mut stack)?;
                    let copied = pop_stack_small(&mut stack)?;
                    let start = pop_stack_small(&mut stack)?;
                    // Port of erts/emulator/beam/external.c:3368 (ENC_BIN_COPY), OTP-29.1.1.
                    let len = bits.div_ceil(8);
                    let amount = len
                        .saturating_sub(copied)
                        .min(budget.saturating_sub(consumed).max(1));
                    let bit_count = (amount * 8).min(bits.saturating_sub(copied * 8));
                    out.write_bitstring(term, copied * 8, bit_count)?;
                    consumed += amount;
                    if copied + amount < len {
                        stack.push(stack_small(start)?);
                        stack.push(stack_small(copied + amount)?);
                        stack.push(stack_small(bits)?);
                        stack.push(term);
                        stack.push(ENC_BIN_COPY);
                    } else {
                        if bits % 8 != 0 {
                            out.mask_last(0xff << (8 - bits % 8));
                        }
                        if len > 64 && record_splits {
                            self.cold().splits.push((start, out.len()));
                        }
                    }
                    continue;
                } else if code == ENC_HASHMAP_NODE_CODE {
                    let node = stack.pop().ok_or(BifError::BADARG)?;
                    cur = Some(push_hashmap_node_tasks(
                        &mut stack,
                        node,
                        Some(ENC_HASHMAP_NODE),
                        Some(ENC_TERM),
                    )?);
                    continue;
                } else if code == ENC_START_SORTING_MAP_CODE {
                    let mut sorting = self.cold().map_sort.take().ok_or(BifError::BADARG)?;
                    let work_budget = budget.saturating_sub(consumed).max(1);
                    consumed += sorting.step(work_budget);
                    if sorting.is_done() {
                        push_sorted_map_tasks(&mut stack, (*sorting).finish());
                    } else {
                        self.cold().map_sort = Some(sorting);
                        stack.push(ENC_START_SORTING_MAP);
                    }
                    continue;
                } else {
                    return Err(BifError::BADARG);
                }
            };
            if !std::mem::take(&mut free_first) {
                consumed += 1;
            }
            match term.classify() {
                TermKind::Number => {
                    if let Some(n) = term.as_small() {
                        write_small(out, n);
                    } else if let Some(header) = term.header() {
                        if header & 63 == 0x18 {
                            // SAFETY: a live boxed FLOAT has one initialized data word.
                            let f = unsafe { term.float_ref() }.ok_or(BifError::BADARG)?.get();
                            if opts.minor == 0 {
                                let s = format!("{f:.20e}");
                                let (mantissa, exponent) = s.split_once('e').unwrap();
                                let exp: i32 = exponent.parse().unwrap();
                                let rendered = format!(
                                    "{mantissa}e{}{:02}",
                                    if exp < 0 { '-' } else { '+' },
                                    exp.abs()
                                );
                                out.push(99);
                                out.extend_from_slice(rendered.as_bytes());
                                out.extend_zeroed(31 - rendered.len());
                            } else {
                                out.push(70);
                                out.extend_from_slice(&f.to_bits().to_be_bytes());
                            }
                        } else {
                            // SAFETY: a live boxed integer has initialized magnitude words.
                            let n = unsafe { term.big_ref() }
                                .ok_or(BifError::BADARG)?
                                .to_bigint();
                            int_bytes(out, &n);
                        }
                    }
                }
                TermKind::Atom => atom_bytes_in(
                    table,
                    out,
                    term.as_atom().ok_or(BifError::BADARG)?,
                    opts.minor,
                )?,
                TermKind::Nil => out.push(106),
                TermKind::List => {
                    // Port of erts/emulator/beam/external.c:3703 (LIST_DEF), OTP-29.1.1.
                    let (len, is_string) = external_string_prefix(term);
                    if is_string {
                        out.push(107);
                        out.extend_from_slice(&(len as u16).to_be_bytes());
                        let mut cursor = term;
                        for _ in 0..len {
                            // SAFETY: external_string_prefix already walked these cons cells.
                            let (head, tail) =
                                unsafe { cursor.cons_ref() }.ok_or(BifError::BADARG)?;
                            out.push(head.as_small().ok_or(BifError::BADARG)? as u8);
                            cursor = tail;
                        }
                        consumed += len;
                    } else {
                        // Port of erts/emulator/beam/external.c (LIST_DEF), OTP-29.1.1.
                        consumed += len / 2;
                        out.push(108);
                        let len_at = out.len();
                        out.extend_from_slice(&0u32.to_be_bytes());
                        // `WSTACK_PUSH2(s, ep, 1)` then `goto encode_one_cons`.
                        stack.push(stack_small(len_at)?);
                        stack.push(stack_small(1)?);
                        cur = Some(encode_one_cons(&mut stack, out, term)?);
                    }
                }
                TermKind::Tuple => {
                    let arity = crate::pure::tuple_arity(term)?;
                    if arity <= 255 {
                        out.extend_from_slice(&[104, arity as u8]);
                    } else {
                        out.push(105);
                        out.extend_from_slice(&(arity as u32).to_be_bytes());
                    }
                    if arity > 0 {
                        // WSTACK_PUSH2(s, ENC_LAST_ARRAY_ELEMENT+i-1, ptr)
                        push_term_task(
                            &mut stack,
                            stack_command((ENC_ARRAY + ((arity as u64) << 3)) as i64),
                            term,
                        );
                    }
                }
                TermKind::Map => {
                    let checked = arinsal_maps::checked_map(term).map_err(|_| BifError::BADARG)?;
                    match checked.kind() {
                        arinsal_maps::CheckedMapKind::Flatmap(_) => {
                            let len = checked.size();
                            out.push(116);
                            out.extend_from_slice(
                                &u32::try_from(len)
                                    .map_err(|_| BifError::SystemLimit)?
                                    .to_be_bytes(),
                            );
                            if len > 0 && opts.deterministic {
                                let pairs = arinsal_maps::term_to_binary_pairs(term)
                                    .map_err(|_| BifError::BADARG)?;
                                self.cold().map_sort = Some(Box::new(MapSort::new(pairs)));
                                stack.push(ENC_START_SORTING_MAP);
                            } else if len > 0 {
                                // WSTACK_PUSH4(s, kptr, vptr, ENC_MAP_PAIR, size)
                                push_term_task(
                                    &mut stack,
                                    stack_command(
                                        (ENC_ARRAY + (((len as u64) << 3) | ENC_PAIR_KIND)) as i64,
                                    ),
                                    term,
                                );
                            }
                        }
                        arinsal_maps::CheckedMapKind::Hashmap(_) => {
                            let children =
                                arinsal_term::MapNodeChildren::new(term).ok_or(BifError::BADARG)?;
                            if children.is_head() {
                                let len = checked.size();
                                out.push(116);
                                out.extend_from_slice(
                                    &u32::try_from(len)
                                        .map_err(|_| BifError::SystemLimit)?
                                        .to_be_bytes(),
                                );
                                if len > 0 && opts.deterministic {
                                    let pairs = arinsal_maps::term_to_binary_pairs(term)
                                        .map_err(|_| BifError::BADARG)?;
                                    self.cold().map_sort = Some(Box::new(MapSort::new(pairs)));
                                    stack.push(ENC_START_SORTING_MAP);
                                } else {
                                    push_hashmap_root_tasks(
                                        &mut stack,
                                        term,
                                        ENC_HASHMAP_NODE,
                                        Some(ENC_TERM),
                                    )?;
                                }
                            } else {
                                push_hashmap_root_tasks(
                                    &mut stack,
                                    term,
                                    ENC_HASHMAP_NODE,
                                    Some(ENC_TERM),
                                )?;
                            }
                        }
                    }
                }
                TermKind::Bitstring => {
                    // SAFETY: the binary owner remains live and no append runs during encoding.
                    let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
                    let bits = view.bit_len();
                    let len = bits.div_ceil(8);
                    let n = u32::try_from(len)
                        .map_err(|_| BifError::SystemLimit)?
                        .to_be_bytes();
                    if bits.is_multiple_of(8) {
                        out.extend_from_slice(&[109, n[0], n[1], n[2], n[3]]);
                    } else {
                        out.extend_from_slice(&[77, n[0], n[1], n[2], n[3], (bits % 8) as u8]);
                    }
                    let start = out.len();
                    if len != 0 {
                        // Port of erts/emulator/beam/external.c (BITSTRING_DEF), OTP-29.1.1.
                        let aligned = view.start_bit().is_multiple_of(8);
                        let copy_payload = bits <= 64 * 8 || !iovec || !aligned;
                        let left = budget.saturating_sub(consumed);
                        if copy_payload && len > left.saturating_mul(8) {
                            stack.push(stack_small(start)?);
                            stack.push(stack_small(0)?);
                            stack.push(stack_small(bits)?);
                            stack.push(term);
                            stack.push(ENC_BIN_COPY);
                        } else {
                            if aligned && bits.is_multiple_of(8) {
                                // copy_binary_to_buffer: one memcpy of the payload.
                                let from = view.start_bit() / 8;
                                out.extend_from_slice(
                                    view.bytes().get(from..from + len).ok_or(BifError::BADARG)?,
                                );
                            } else {
                                out.write_bitstring(term, 0, bits)?;
                                if bits % 8 != 0 {
                                    out.mask_last(0xff << (8 - bits % 8));
                                }
                            }
                            if len > 64 && record_splits {
                                self.cold().splits.push((start, out.len()));
                            }
                        }
                    }
                }
                TermKind::Pid | TermKind::Port | TermKind::Ref => {
                    resolve_local_node(&mut opts, node_source);
                    let identity =
                        local_identity(term.identity().ok_or(BifError::BADARG)?, opts.local_node);
                    match identity {
                        Identity::Pid {
                            node,
                            creation,
                            index,
                            serial,
                        } => {
                            out.push(88);
                            // Port of erts/emulator/beam/external.c:3651 (local pid node), OTP-29.1.1.
                            write_node(out, node, opts)?;
                            out.extend_from_slice(&index.to_be_bytes());
                            out.extend_from_slice(&serial.to_be_bytes());
                            out.extend_from_slice(&local_creation(creation, opts).to_be_bytes());
                        }
                        Identity::Port { node, creation, id } => {
                            out.push(120);
                            write_node(out, node, opts)?;
                            out.extend_from_slice(&id.to_be_bytes());
                            out.extend_from_slice(&local_creation(creation, opts).to_be_bytes());
                        }
                        Identity::Ref {
                            node,
                            creation,
                            ids,
                        } => {
                            // Port of erts/emulator/beam/external.c (enc_term, reference
                            // case), OTP-29.1.1: the numbers leave the term.
                            term.save_magic_ref();
                            out.push(90);
                            out.extend_from_slice(&(ids.len() as u16).to_be_bytes());
                            write_node(out, node, opts)?;
                            out.extend_from_slice(&local_creation(creation, opts).to_be_bytes());
                            for id in ids {
                                out.extend_from_slice(&id.to_be_bytes());
                            }
                        }
                    }
                }
                TermKind::Fun => match fun_of(term)? {
                    FunRef::Export { entry } => {
                        out.push(113);
                        atom_bytes_in(table, out, entry.module, opts.minor)?;
                        atom_bytes_in(table, out, entry.function, opts.minor)?;
                        write_small(out, i64::from(entry.arity));
                    }
                    FunRef::Local { entry, free_vars } => {
                        out.push(112);
                        let at = out.len();
                        out.extend_from_slice(&[0; 4]);
                        out.push(entry.arity);
                        out.extend_from_slice(&entry.uniq);
                        out.extend_from_slice(&entry.index.to_be_bytes());
                        out.extend_from_slice(&(free_vars.len() as u32).to_be_bytes());
                        atom_bytes_in(table, out, entry.module, opts.minor)?;
                        write_small(out, i64::from(entry.old_index));
                        write_small(out, i64::from(entry.old_uniq));
                        stack.push(stack_small(at)?);
                        stack.push(ENC_PATCH_FUN_SIZE);
                        let view = fun_of(term)?;
                        for i in (0..view.num_free()).rev() {
                            push_term_task(
                                &mut stack,
                                ENC_TERM,
                                view.free(i).ok_or(BifError::BADARG)?,
                            );
                        }
                        push_term_task(&mut stack, ENC_TERM, entry.pid);
                    }
                },
                TermKind::Record => {
                    // Port of erts/emulator/beam/external.c:4010-4031, OTP-29.1.1.
                    let record = record_of(term)?;
                    out.push(67);
                    out.extend_from_slice(&(record.len() as u32).to_be_bytes());
                    out.push(u8::from(record.is_exported()));
                    atom_bytes_in(table, out, record.module(), opts.minor)?;
                    atom_bytes_in(table, out, record.name(), opts.minor)?;
                    for i in 0..record.len() {
                        let sorted = record.sorted_index(i).ok_or(BifError::BADARG)?;
                        atom_bytes_in(
                            table,
                            out,
                            record.key(sorted).ok_or(BifError::BADARG)?,
                            opts.minor,
                        )?;
                    }
                    for i in (0..record.len()).rev() {
                        let sorted = record.sorted_index(i).ok_or(BifError::BADARG)?;
                        push_term_task(
                            &mut stack,
                            ENC_TERM,
                            record.value(sorted).ok_or(BifError::BADARG)?,
                        );
                    }
                }
                _ => return Err(BifError::Unsupported("ETF representation")),
            }
        }
        let done = stack.is_empty()
            && cur.is_none()
            && self
                .cold
                .as_ref()
                .is_none_or(|cold| cold.map_sort.is_none());
        self.opts = opts;
        stack.save(&mut self.work);
        self.current_term = cur;
        self.free_first = !done;
        if out.failed() || (done && !iovec && out.len() != self.encoded_size) {
            return Err(BifError::SystemLimit);
        }
        Ok((done, if done { consumed } else { budget.max(consumed) }))
    }

    /// Finish compression and return the serialized byte vector.
    pub fn finish_binary(self) -> Result<Vec<u8>, BifError> {
        self.finish_binary_buffer().map(SmallVec::into_vec)
    }

    /// Finish as an inline buffer when the ETF output is small.
    pub fn finish_binary_buffer(mut self) -> Result<SmallVec<[u8; 64]>, BifError> {
        self.patch_local_hash();
        if self.opts.compressed.is_some_and(|level| level > 0) {
            return encode_bytes(self.take_out(), self.opts).map(SmallVec::from_vec);
        }
        Ok(SmallVec::from_vec(self.take_out()))
    }

    fn take_out(&mut self) -> Vec<u8> {
        self.cold.take().map(|cold| cold.out).unwrap_or_default()
    }

    fn patch_local_hash(&mut self) {
        if self.opts.local {
            let out = &mut self.cold().out;
            let hash = local_term_hash(&out[6..]);
            out[2..6].copy_from_slice(&hash.to_be_bytes());
        }
    }

    /// Finish as `term_to_iovec/1,2`, preserving large-binary split boundaries.
    pub fn finish_iovec(mut self) -> Result<(Vec<Vec<u8>>, bool), BifError> {
        self.patch_local_hash();
        if self.opts.compressed.is_some_and(|level| level > 0) {
            return Ok((vec![encode_bytes(self.take_out(), self.opts)?], true));
        }
        let EncodeCold { out, splits, .. } = *self.cold.take().unwrap_or_default();
        let mut at = 0;
        let mut parts = Vec::new();
        for (start, end) in splits {
            if start > at {
                parts.push(out[at..start].to_vec());
            }
            parts.push(out[start..end].to_vec());
            at = end;
        }
        if at < out.len() {
            parts.push(out[at..].to_vec());
        }
        Ok((parts, false))
    }
}

/// Encode one term with the default `term_to_binary/1` options without running its BIF body.
///
/// Port of erts/emulator/beam/external.c:3305 (`erts_term_to_binary`), OTP-29.1.1.
pub fn encode_term_to_binary(term: Term) -> Result<Vec<u8>, BifError> {
    let mut walk = EncodeWalk::new(&[term])?;
    walk.step(usize::MAX)?;
    walk.finish_binary()
}

fn encode_plain_with_splits(term: Term, opts: EncodeOpts) -> Result<EncodedWithSplits, BifError> {
    let mut walk = EncodeWalk::start(term, opts);
    walk.record_splits = true;
    walk.step(usize::MAX)?;
    walk.patch_local_hash();
    let EncodeCold { out, splits, .. } = *walk.cold.take().unwrap_or_default();
    Ok((out, splits))
}

// Port of erts/emulator/beam/external.c:3244 (enc_term, local pid/port/ref identity), OTP-29.1.1.
fn local_identity(identity: Identity, local_node: Option<(arinsal_term::Atom, u32)>) -> Identity {
    let Some((local_node, local_creation)) = local_node else {
        return identity;
    };
    match identity {
        Identity::Pid {
            node,
            creation: 0,
            index,
            serial,
        } if node == atoms::NONAME => Identity::Pid {
            node: local_node,
            creation: local_creation,
            index,
            serial,
        },
        Identity::Port {
            node,
            creation: 0,
            id,
        } if node == atoms::NONAME => Identity::Port {
            node: local_node,
            creation: local_creation,
            id,
        },
        Identity::Ref {
            node,
            creation: 0,
            ids,
        } if node == atoms::NONAME => Identity::Ref {
            node: local_node,
            creation: local_creation,
            ids,
        },
        other => other,
    }
}

// Port of erts/emulator/beam/external.c:3651 (NIL_EXT node when encoding local), OTP-29.1.1.
fn write_node(
    out: &mut impl ByteOutput,
    node: arinsal_term::Atom,
    opts: EncodeOpts,
) -> Result<(), BifError> {
    if opts.local {
        out.push(106);
        Ok(())
    } else {
        atom_term(out, Term::atom(node), opts.minor)
    }
}

fn local_creation(creation: u32, opts: EncodeOpts) -> u32 {
    if opts.local { 0 } else { creation }
}

fn encode_plain(term: Term, opts: EncodeOpts) -> Result<Vec<u8>, BifError> {
    encode_plain_with_splits(term, opts).map(|(bytes, _)| bytes)
}

fn encode(term: Term, opts: EncodeOpts) -> Result<Vec<u8>, BifError> {
    let plain = encode_plain(term, opts)?;
    encode_bytes(plain, opts)
}

fn encode_bytes(plain: Vec<u8>, opts: EncodeOpts) -> Result<Vec<u8>, BifError> {
    if let Some(level) = opts.compressed.filter(|n| *n > 0) {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), Compression::new(level as u32));
        z.write_all(&plain[1..])
            .map_err(|_| BifError::SystemLimit)?;
        let bytes = z.finish().map_err(|_| BifError::SystemLimit)?;
        // Port of erts/emulator/beam/external.c:2276-2300, OTP-29.1.1.
        if bytes.len() + 5 < plain.len() {
            let mut compressed = vec![131, 80];
            compressed.extend_from_slice(&((plain.len() - 1) as u32).to_be_bytes());
            compressed.extend_from_slice(&bytes);
            return Ok(compressed);
        }
    }
    Ok(plain)
}

fn result_binary(ctx: &mut Ctx<'_>, bytes: &[u8]) -> Result<Term, BifError> {
    TermBuilder::new(&mut Heap(&mut ctx.heap))
        .binary(bytes)
        .map_err(|_| BifError::SystemLimit)
}

fn term_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match term_to_binary_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn term_to_binary_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let opts = options(args.get(1).copied())?;
    let mut encoder = EncodeWalk::start(args[0], opts);
    encoder.step_size(usize::MAX)?;
    let size = encoder.encoded_size().ok_or(BifError::SystemLimit)?;
    if encoder.finishes_simple() {
        let binary = encoder.encode_simple_binary(&mut ctx.heap)?;
        // Port of erts/emulator/beam/external.c (TTBSize simple path), OTP-29.1.1:
        // erts_term_to_binary_simple charges exactly one reduction, independent of size.
        ctx.charge_reductions(1);
        return Ok(binary);
    }
    if !encoder.uses_compression() {
        match encoder.encode_into_refc(&mut ctx.heap, usize::MAX)? {
            (RefcEncoded::Done(binary), _) => {
                ctx.charge_reductions(size);
                return Ok(binary);
            }
            (RefcEncoded::Partial(_), _) => return Err(BifError::SystemLimit),
        }
    }
    let mut heap = Heap(&mut ctx.heap);
    let binary = crate::allocate_iolist_binary(&mut heap, size)?;
    crate::with_iolist_binary_output(binary, |destination| {
        match encoder.step_into(destination, usize::MAX)? {
            (true, _) => Ok(()),
            (false, _) => Err(BifError::SystemLimit),
        }
    })?;
    writable_finalize(binary);
    if encoder.uses_compression() {
        let compressed = crate::allocate_iolist_binary(&mut heap, size)?;
        let progress = crate::with_binary_bytes(binary, |view| {
            crate::with_iolist_binary_output(compressed, |destination| {
                destination[..6].copy_from_slice(&[131, 80, 0, 0, 0, 0]);
                destination[2..6].copy_from_slice(&((size - 1) as u32).to_be_bytes());
                encoder.compress_into(&view.bytes()[1..], &mut destination[6..], usize::MAX)
            })
        })??;
        if progress.0 && encoder.compression_is_useful() {
            let final_size = 6usize
                .checked_add(
                    encoder
                        .compressed_payload_len()
                        .ok_or(BifError::SystemLimit)?,
                )
                .ok_or(BifError::SystemLimit)?;
            writable_resize_private(
                compressed,
                final_size.checked_mul(8).ok_or(BifError::SystemLimit)?,
            )
            .map_err(|_| BifError::SystemLimit)?;
            writable_finalize(compressed);
            ctx.charge_reductions(final_size);
            return Ok(compressed);
        }
        crate::finish_iolist_binary_output(compressed);
        ctx.charge_reductions(size);
        return Ok(binary);
    }
    ctx.charge_reductions(size);
    Ok(binary)
}

fn external_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match external_size_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn external_size_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut encoder = EncodeWalk::new_external_size(args)?;
    encoder.step_size(usize::MAX)?;
    let size = encoder.encoded_size().ok_or(BifError::SystemLimit)?;
    // Port of erts/emulator/beam/external.c (external_size_1), OTP-29.1.1: the size
    // is computed in one go without charging reductions.
    integer(ctx, size)
}

fn term_to_iovec(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match term_to_iovec_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn term_to_iovec_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let opts = options(args.get(1).copied())?;
    if opts.compressed.is_some_and(|level| level > 0) {
        let bytes = encode(args[0], opts)?;
        ctx.charge_reductions(bytes.len());
        return result_binary(ctx, &bytes);
    }
    let (bytes, splits) = encode_plain_with_splits(args[0], opts)?;
    ctx.charge_reductions(bytes.len());
    let mut at = 0;
    let mut parts = Vec::new();
    for (start, end) in splits {
        if start > at {
            parts.push(result_binary(ctx, &bytes[at..start])?);
        }
        parts.push(result_binary(ctx, &bytes[start..end])?);
        at = end;
    }
    if at < bytes.len() {
        parts.push(result_binary(ctx, &bytes[at..])?);
    }
    Ok(make_list(ctx, parts, Term::NIL))
}

#[derive(Default)]
struct DecodeOpts {
    safe: bool,
    used: bool,
}

fn decode_options(term: Option<Term>) -> Result<DecodeOpts, BifError> {
    let mut opts = DecodeOpts::default();
    let Some(mut tail) = term else {
        return Ok(opts);
    };
    while tail != Term::NIL {
        // SAFETY: the option list remains live and stable during the BIF.
        let (head, next) = unsafe { tail.cons_ref() }.ok_or_else(badopt)?;
        tail = next;
        match atom_text(head) {
            Some("safe") => opts.safe = true,
            Some("used") => opts.used = true,
            _ => return Err(badopt()),
        }
    }
    Ok(opts)
}

fn badopt() -> BifError {
    BifError::Badarg {
        cause: Some(Term::atom(arinsal_term::atoms::BADOPT)),
    }
}

enum DecodeInput<'a> {
    Inline(SmallVec<[u8; 64]>),
    Borrowed {
        bytes: &'a [u8],
        term: Term,
        offset: usize,
        len: usize,
    },
    Refc {
        owner: OwnedBinaryRef,
        offset: usize,
        len: usize,
    },
}

impl DecodeInput<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Inline(bytes) => bytes,
            Self::Borrowed { bytes, .. } => bytes,
            Self::Refc { owner, offset, len } => owner
                .payload(*offset, *len)
                .expect("retained ETF bytes remain within the Binary allocation"),
        }
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}
impl Reader<'_> {
    fn take(&mut self, n: usize) -> Result<&[u8], BifError> {
        let end = self.at.checked_add(n).ok_or(BifError::BADARG)?;
        let part = self
            .bytes
            .get(self.at..end)
            .ok_or(BifError::Unsupported("incomplete ETF input"))?;
        self.at = end;
        Ok(part)
    }
    fn u8(&mut self) -> Result<u8, BifError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, BifError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, BifError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, BifError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }
    fn atom<H: HeapAlloc>(
        &mut self,
        safe: bool,
        ctx: &mut Option<&mut Ctx<'_, H>>,
    ) -> Result<(Term, Option<String>), BifError> {
        let tag = self.u8()?;
        let (len, utf8) = match tag {
            100 => (self.u16()? as usize, false),
            115 => (self.u8()? as usize, false),
            118 => (self.u16()? as usize, true),
            119 => (self.u8()? as usize, true),
            _ => return Err(BifError::BADARG),
        };
        let raw = self.take(len)?;
        // UTF-8 and ASCII latin1 are decoded from the input bytes. A String is
        // built only for non-ASCII latin1, which is not valid UTF-8 as-is.
        let owned;
        let name = if utf8 || raw.is_ascii() {
            std::str::from_utf8(raw).map_err(|_| BifError::BADARG)?
        } else {
            owned = raw.iter().map(|b| char::from(*b)).collect::<String>();
            owned.as_str()
        };
        if name.chars().count() > 255 {
            return Err(BifError::BADARG);
        }
        let atoms = global_atoms();
        let atom = if safe {
            atoms.get(name).ok_or(BifError::BADARG)?
        } else if ctx.is_some() {
            atoms.intern(name).map_err(|_| BifError::SystemLimit)?
        } else {
            atoms.get(name).unwrap_or(arinsal_term::atoms::NONAME)
        };
        let unknown = (atom == arinsal_term::atoms::NONAME).then(|| name.to_owned());
        Ok((Term::atom(atom), unknown))
    }
}

enum Shape {
    /// `None` is an interned atom. `Some` keeps the text only when the index is `NONAME`.
    Atom(Option<String>),
    Int(i64),
    Pid,
    Other,
}

enum FrameKind {
    Local {
        hash: u32,
        term_start: usize,
    },
    Tuple {
        slots: Option<arinsal_term::HeapBlockBuilder>,
    },
    List {
        slots: Option<ConsListBuilder>,
    },
    Map {
        keys: SmallVec<[Term; 4]>,
        map_values: SmallVec<[Term; 4]>,
    },
    Export,
    Fun {
        arity: u8,
        uniq: [u8; 16],
        index: u32,
        free: usize,
    },
    Record {
        exported: bool,
        fields: usize,
    },
}
struct Frame {
    kind: FrameKind,
    left: usize,
    values: SmallVec<[Term; 4]>,
    shapes: SmallVec<[Shape; 4]>,
}

fn built<H: HeapAlloc>(
    ctx: &mut Option<&mut Ctx<'_, H>>,
    f: impl FnOnce(&mut TermBuilder<'_, Heap<'_, H>>) -> Result<Term, arinsal_term::TermError>,
) -> Result<Term, BifError> {
    if let Some(ctx) = ctx.as_deref_mut() {
        let mut heap = Heap(&mut ctx.heap);
        f(&mut TermBuilder::new(&mut heap)).map_err(map_term_build_error)
    } else {
        Ok(Term::NIL)
    }
}

fn map_term_build_error(error: arinsal_term::TermError) -> BifError {
    match error {
        arinsal_term::TermError::SystemLimit => BifError::SystemLimit,
        _ => BifError::BADARG,
    }
}

// Port of erts/emulator/beam/external.c (dec_term, tuple_loop), OTP-29.1.1.
fn reserve_tuple_slots<H: HeapAlloc>(
    ctx: &mut Option<&mut Ctx<'_, H>>,
    arity: usize,
) -> Result<Option<arinsal_term::HeapBlockBuilder>, BifError> {
    let Some(ctx) = ctx.as_deref_mut() else {
        return Ok(None);
    };
    let mut heap = Heap(&mut ctx.heap);
    TermBuilder::new(&mut heap)
        .reserve_tuple_block(arity)
        .map(Some)
        .map_err(map_term_build_error)
}

// Port of erts/emulator/beam/external.c (dec_term, next child slot), OTP-29.1.1.
fn accept_child(frame: &mut Frame, term: Term, shape: Shape) -> Result<(), BifError> {
    match &mut frame.kind {
        FrameKind::Tuple { slots } => {
            if let Some(slots) = slots {
                slots.write_term(term).map_err(map_term_build_error)?;
            }
        }
        FrameKind::Map { keys, map_values } => {
            if frame.left.is_multiple_of(2) {
                keys.push(term);
            } else {
                map_values.push(term);
            }
        }
        FrameKind::List { slots: Some(slots) } if frame.left > 1 => {
            slots.append(term).map_err(map_term_build_error)?;
        }
        _ => {
            frame.values.push(term);
            frame.shapes.push(shape);
        }
    }
    Ok(())
}

fn finish<H: HeapAlloc>(
    frame: Frame,
    ctx: &mut Option<&mut Ctx<'_, H>>,
) -> Result<(Term, Shape), BifError> {
    let values = frame.values;
    match frame.kind {
        FrameKind::Local { .. } => Err(BifError::BADARG),
        FrameKind::Tuple { slots } => {
            let term = if let Some(slots) = slots {
                slots.finish().map_err(map_term_build_error)?
            } else {
                Term::NIL
            };
            Ok((term, Shape::Other))
        }
        FrameKind::List { slots: Some(slots) } => {
            let tail = values.into_iter().next().ok_or(BifError::BADARG)?;
            let term = slots.finish(tail).map_err(map_term_build_error)?;
            Ok((term, Shape::Other))
        }
        FrameKind::List { slots: None } => {
            let mut it = values.into_iter().rev();
            let mut tail = it.next().ok_or(BifError::BADARG)?;
            if ctx.is_some() {
                for head in it {
                    tail = built(ctx, |b| b.cons(head, tail))?;
                }
            }
            Ok((tail, Shape::Other))
        }
        FrameKind::Map {
            mut keys,
            mut map_values,
        } => {
            // Port of erts/emulator/beam/external.c:5047-5060, 5428-5445
            // (decoded key/value arrays and bottom-up map construction), OTP-29.1.1.
            if ctx.is_some() {
                let ctx = ctx.as_deref_mut().unwrap();
                if keys.len() <= 32 {
                    for index in 1..keys.len() {
                        let mut current = index;
                        while current > 0 {
                            match flat_key_cmp(keys[current], keys[current - 1]) {
                                Ordering::Greater => break,
                                Ordering::Equal => return Err(BifError::BADARG),
                                Ordering::Less => {
                                    keys.swap(current, current - 1);
                                    map_values.swap(current, current - 1);
                                    current -= 1;
                                }
                            }
                        }
                    }
                    let map = TermBuilder::new(&mut ctx.heap)
                        .flatmap_from_sorted_arrays(&keys, &map_values)
                        .map_err(map_term_build_error)?;
                    Ok((map, Shape::Other))
                } else {
                    let map =
                        hashmap_from_ks_and_vs_extra(&keys, &map_values, None, true, &mut ctx.heap)
                            .map_err(map_term_build_error)?
                            .ok_or(BifError::BADARG)?;
                    Ok((map, Shape::Other))
                }
            } else {
                Ok((Term::NIL, Shape::Other))
            }
        }
        FrameKind::Export => {
            if !matches!(
                frame.shapes.as_slice(),
                [Shape::Atom(_), Shape::Atom(_), Shape::Int(0..=255)]
            ) {
                return Err(BifError::BADARG);
            }
            let term = if ctx.is_some() {
                let entry = Arc::new(ExportEntry::new(
                    values[0].as_atom().unwrap(),
                    values[1].as_atom().unwrap(),
                    values[2].as_small().ok_or(BifError::BADARG)? as u8,
                ));
                built(ctx, |b| b.export_fun(entry))?
            } else {
                Term::NIL
            };
            Ok((term, Shape::Other))
        }
        FrameKind::Fun {
            arity,
            uniq,
            index,
            free,
        } => {
            if !matches!(frame.shapes.first(), Some(Shape::Atom(_)))
                || !matches!(frame.shapes.get(1), Some(Shape::Int(0..=4_294_967_295)))
                || !matches!(frame.shapes.get(2), Some(Shape::Int(0..=4_294_967_295)))
                || !matches!(frame.shapes.get(3), Some(Shape::Pid))
            {
                return Err(BifError::BADARG);
            }
            let term = if ctx.is_some() {
                let entry = Arc::new(FunEntry {
                    dispatch_target: Default::default(),
                    pend_purge_address: Default::default(),
                    module: values[0].as_atom().unwrap(),
                    arity,
                    index,
                    uniq,
                    old_index: values[1].as_small().ok_or(BifError::BADARG)? as u32,
                    old_uniq: values[2].as_small().ok_or(BifError::BADARG)? as u32,
                    pid: values[3],
                    dispatch: Default::default(),
                    dispatch_code: Default::default(),
                    dispatch_epoch: Default::default(),
                });
                // Port of erts/emulator/beam/external.c:5162-5168, OTP-29.1.1.
                built(ctx, |b| b.local_fun_stub(entry, &values[4..4 + free]))?
            } else {
                Term::NIL
            };
            Ok((term, Shape::Other))
        }
        FrameKind::Record { exported, fields } => {
            let mut seen = std::collections::HashSet::new();
            let mut unknown = std::collections::HashSet::new();
            for (index, shape) in frame.shapes[..fields + 2].iter().enumerate() {
                match shape {
                    Shape::Atom(None) => {
                        if index >= 2 {
                            let atom = values[index].as_atom().ok_or(BifError::BADARG)?;
                            if !seen.insert(atom) {
                                return Err(BifError::BADARG);
                            }
                        }
                    }
                    Shape::Atom(Some(name)) => {
                        if index >= 2 && !unknown.insert(name.as_str()) {
                            return Err(BifError::BADARG);
                        }
                    }
                    _ => return Err(BifError::BADARG),
                }
            }
            let term = if ctx.is_some() {
                let pairs: SmallVec<[(arinsal_term::Atom, Term); 4]> = (0..fields)
                    .map(|i| (values[i + 2].as_atom().unwrap(), values[i + fields + 2]))
                    .collect();
                built(ctx, |b| {
                    b.native_record(
                        values[0].as_atom().unwrap(),
                        values[1].as_atom().unwrap(),
                        exported,
                        &pairs,
                    )
                })?
            } else {
                Term::NIL
            };
            Ok((term, Shape::Other))
        }
    }
}

fn count_ok(count: usize, remaining: usize, input_complete: bool) -> Result<(), BifError> {
    if count > remaining {
        if input_complete {
            Err(BifError::BADARG)
        } else {
            Err(BifError::Unsupported("incomplete ETF input"))
        }
    } else {
        Ok(())
    }
}

fn parse_step<H: HeapAlloc>(
    r: &mut Reader,
    stack: &mut SmallVec<[Frame; 4]>,
    safe: bool,
    local_node: Option<(arinsal_term::Atom, u32)>,
    mut ctx: Option<&mut Ctx<'_, H>>,
    budget: usize,
    input_complete: bool,
) -> Result<Option<(Term, usize)>, BifError> {
    // Port of erts/emulator/beam/external.c:116 (`B2T_BYTES_PER_REDUCTION` 128) and
    // the dec_term reds loop, OTP-29.1.1. `budget` is a byte limit. A tag that
    // starts inside the limit may finish past it; the next call then traps.
    let byte_limit = r.at.saturating_add(budget);
    while r.at < byte_limit {
        let tag = r.u8()?;
        let result: Option<(Term, Shape)> = match tag {
            121 => {
                // Port of erts/emulator/beam/external.c:6437-6445 (LOCAL_EXT), OTP-29.1.1.
                let hash = r.u32()?;
                stack.push(Frame {
                    kind: FrameKind::Local {
                        hash,
                        term_start: r.at,
                    },
                    left: 1,
                    values: SmallVec::new(),
                    shapes: SmallVec::new(),
                });
                None
            }
            97 | 98 => {
                // Port of erts/emulator/beam/external.c:4452 (SMALL_INTEGER_EXT / INTEGER_EXT
                // make_small), OTP-29.1.1. Both tags fit in an immediate small.
                let n = if tag == 97 {
                    r.u8()? as i64
                } else {
                    r.u32()? as i32 as i64
                };
                Some((Term::small(n).ok_or(BifError::BADARG)?, Shape::Int(n)))
            }
            110 | 111 => {
                let len = if tag == 110 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                let sign = r.u8()?;
                let number = BigInt::from_bytes_le(
                    if sign == 0 { Sign::Plus } else { Sign::Minus },
                    r.take(len)?,
                );
                let shape = number.to_i64().map_or(Shape::Other, Shape::Int);
                Some((built(&mut ctx, |b| b.int_from_bigint(&number))?, shape))
            }
            70 | 99 => {
                let f = if tag == 70 {
                    f64::from_bits(r.u64()?)
                } else {
                    let raw = r.take(31)?;
                    let end = raw.iter().position(|b| *b == 0).unwrap_or(31);
                    std::str::from_utf8(&raw[..end])
                        .map_err(|_| BifError::BADARG)?
                        .parse::<f64>()
                        .map_err(|_| BifError::BADARG)?
                };
                if !f.is_finite() {
                    return Err(BifError::BADARG);
                }
                Some((built(&mut ctx, |b| b.float(f))?, Shape::Other))
            }
            100 | 115 | 118 | 119 => {
                r.at -= 1;
                let (term, unknown) = r.atom(safe, &mut ctx)?;
                Some((term, Shape::Atom(unknown)))
            }
            73 | 75 => {
                // Port of external.c:5177-5190 (internal atom references), OTP-29.1.1.
                let index = if tag == 73 {
                    r.u16()? as u32
                } else {
                    let b = r.take(3)?;
                    u32::from_be_bytes([0, b[0], b[1], b[2]])
                };
                let atom = arinsal_term::Atom(index);
                if global_atoms().text(atom).is_none() {
                    return Err(BifError::BADARG);
                }
                Some((Term::atom(atom), Shape::Atom(None)))
            }
            106 => Some((Term::NIL, Shape::Other)),
            104 | 105 => {
                let n = if tag == 104 {
                    r.u8()? as usize
                } else {
                    r.u32()? as usize
                };
                count_ok(n, r.bytes.len() - r.at, input_complete)?;
                if n == 0 {
                    Some((built(&mut ctx, |b| b.tuple(&[]))?, Shape::Other))
                } else {
                    let slots = reserve_tuple_slots(&mut ctx, n)?;
                    stack.push(Frame {
                        kind: FrameKind::Tuple { slots },
                        left: n,
                        values: SmallVec::new(),
                        shapes: SmallVec::new(),
                    });
                    None
                }
            }
            107 => {
                // Port of erts/emulator/beam/external.c:4615 (STRING_EXT), OTP-29.1.1.
                let n = r.u16()? as usize;
                let raw = r.take(n)?;
                let tail = if let Some(ctx) = ctx.as_deref_mut() {
                    TermBuilder::new(&mut ctx.heap)
                        .byte_string_list(raw)
                        .map_err(|error| match error {
                            arinsal_term::TermError::SystemLimit => BifError::SystemLimit,
                            _ => BifError::BADARG,
                        })?
                } else {
                    Term::NIL
                };
                Some((tail, Shape::Other))
            }
            108 | 116 => {
                let n = r.u32()? as usize;
                let count = if tag == 108 {
                    n.checked_add(1)
                } else {
                    n.checked_mul(2)
                }
                .ok_or(BifError::BADARG)?;
                count_ok(count, r.bytes.len() - r.at, input_complete)?;
                if count == 0 {
                    let t = if let Some(ctx) = ctx.as_deref_mut() {
                        arinsal_maps::from_pairs(&[], &mut ctx.heap)
                            .map_err(|_| BifError::BADARG)?
                    } else {
                        Term::NIL
                    };
                    Some((t, Shape::Other))
                } else {
                    stack.push(Frame {
                        kind: if tag == 108 {
                            let slots = if let Some(context) = ctx.as_deref_mut() {
                                Some(
                                    TermBuilder::new(&mut context.heap)
                                        .reserve_cons_list(n)
                                        .map_err(map_term_build_error)?,
                                )
                            } else {
                                None
                            };
                            FrameKind::List { slots }
                        } else {
                            FrameKind::Map {
                                keys: SmallVec::with_capacity(n.min(1024)),
                                map_values: SmallVec::with_capacity(n.min(1024)),
                            }
                        },
                        left: count,
                        values: if tag == 108 {
                            SmallVec::with_capacity(count.min(1024))
                        } else {
                            SmallVec::new()
                        },
                        shapes: SmallVec::new(),
                    });
                    None
                }
            }
            109 | 77 => {
                let n = r.u32()? as usize;
                let bits = if tag == 77 { r.u8()? as usize } else { 8 };
                if tag == 77 && (n == 0 || !(1..=8).contains(&bits)) {
                    return Err(BifError::BADARG);
                }
                let raw = r.take(n)?;
                let bit_len = if tag == 109 {
                    n.checked_mul(8)
                } else {
                    n.checked_sub(1)
                        .and_then(|v| v.checked_mul(8))
                        .and_then(|v| v.checked_add(bits))
                }
                .ok_or(BifError::BADARG)?;
                // Port of erts/emulator/beam/external.c:4940-4997 (`dec_term` binary cases),
                // OTP-29.1.1: short payloads are heap bits and long payloads copy to a new Binary.
                let t = built(&mut ctx, |b| b.bitstring(raw, bit_len))?;
                Some((t, Shape::Other))
            }
            103 | 88 | 102 | 89 | 120 | 101 | 114 | 90 => {
                let count = if tag == 101 {
                    1
                } else if tag == 114 || tag == 90 {
                    r.u16()? as usize
                } else {
                    0
                };
                if matches!(tag, 101 | 114 | 90) && !(1..=5).contains(&count) {
                    return Err(BifError::BADARG);
                }
                let local_ext = stack
                    .iter()
                    .any(|frame| matches!(&frame.kind, FrameKind::Local { .. }));
                let (node_term, _) = if local_ext && r.bytes.get(r.at) == Some(&106) {
                    r.at += 1;
                    (Term::atom(arinsal_term::atoms::NONAME), None)
                } else {
                    r.atom(safe, &mut ctx)?
                };
                let node = node_term.as_atom().unwrap();
                let mut ids = [0; 5];
                let identity = if tag == 103 || tag == 88 {
                    let id = r.u32()?;
                    let serial = r.u32()?;
                    let creation = if tag == 103 { r.u8()? as u32 } else { r.u32()? };
                    if tag == 103 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (id as u64, serial, creation, 0)
                } else if matches!(tag, 102 | 89 | 120) {
                    let id = if tag == 120 {
                        r.u64()?
                    } else {
                        r.u32()? as u64
                    };
                    let creation = if tag == 102 { r.u8()? as u32 } else { r.u32()? };
                    if tag == 102 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (id, 0, creation, 0)
                } else if tag == 101 {
                    let id = r.u32()?;
                    let creation = r.u8()? as u32;
                    if id >= (1 << 18) || creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    ids[0] = id;
                    (0, 0, creation, 1)
                } else {
                    let creation = if tag == 90 { r.u32()? } else { r.u8()? as u32 };
                    if tag != 90 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    for (i, slot) in ids.iter_mut().take(count).enumerate() {
                        let id = r.u32()?;
                        if i == 0 && tag != 90 && id >= (1 << 18) {
                            return Err(BifError::BADARG);
                        }
                        *slot = id;
                    }
                    (0, 0, creation, count)
                };
                let (id, serial, creation, ids_len) = identity;
                // Port of erts/emulator/beam/external.c (dec_is_this_node, dec_pid, dec_term),
                // OTP-29.1.1: local identities use the current node entry and become internal terms.
                let is_this_node = local_node.is_some_and(|(local_name, local_creation)| {
                    node == local_name && creation == local_creation
                });
                let t = if ctx.is_none() {
                    Term::NIL
                } else if tag == 103 || tag == 88 {
                    if (node == arinsal_term::atoms::NONAME && creation == 0) || is_this_node {
                        Term::pid(id as u32, serial).ok_or(BifError::BADARG)?
                    } else {
                        built(&mut ctx, |b| {
                            b.external_pid(Node::new(node, creation), id as u32, serial)
                        })?
                    }
                } else if matches!(tag, 102 | 89 | 120) {
                    if (node == arinsal_term::atoms::NONAME && creation == 0) || is_this_node {
                        Term::port(id).ok_or(BifError::BADARG)?
                    } else {
                        built(&mut ctx, |b| b.external_port(Node::new(node, creation), id))?
                    }
                } else if (node == arinsal_term::atoms::NONAME && creation == 0) || is_this_node {
                    // Port of erts/emulator/beam/external.c (dec_term, NEWER_REFERENCE_EXT),
                    // OTP-29.1.1: numbers of a saved magic reference give that reference.
                    let mut local = [0; 3];
                    for (slot, value) in local.iter_mut().zip(&ids[..ids_len]) {
                        *slot = *value;
                    }
                    let saved = (local[2] == u32::MAX)
                        .then(|| {
                            arinsal_term::MagicRef::lookup_saved(
                                u64::from(local[0]) | (u64::from(local[1]) << 32),
                            )
                        })
                        .flatten();
                    match saved {
                        Some(owner) => built(&mut ctx, |b| b.magic_ref(owner))?,
                        None => built(&mut ctx, |b| b.local_ref(local))?,
                    }
                } else {
                    built(&mut ctx, |b| {
                        b.external_ref(Node::new(node, creation), &ids[..ids_len])
                    })?
                };
                Some((
                    t,
                    if tag == 103 || tag == 88 {
                        Shape::Pid
                    } else {
                        Shape::Other
                    },
                ))
            }
            113 => {
                stack.push(Frame {
                    kind: FrameKind::Export,
                    left: 3,
                    values: SmallVec::new(),
                    shapes: SmallVec::new(),
                });
                None
            }
            112 => {
                let _size = r.u32()?;
                let arity = r.u8()?;
                let uniq = r.take(16)?.try_into().unwrap();
                let index = r.u32()?;
                let free = r.u32()? as usize;
                count_ok(free.saturating_add(4), r.bytes.len() - r.at, input_complete)?;
                if free > 255 {
                    return Err(BifError::Unsupported(
                        "fun with more than 255 free variables",
                    ));
                }
                stack.push(Frame {
                    kind: FrameKind::Fun {
                        arity,
                        uniq,
                        index,
                        free,
                    },
                    left: free + 4,
                    values: SmallVec::new(),
                    shapes: SmallVec::new(),
                });
                None
            }
            67 => {
                let fields = r.u32()? as usize;
                if fields > (1 << 24) - 2 {
                    return Err(BifError::SystemLimit);
                }
                let exported = match r.u8()? {
                    0 => false,
                    1 => true,
                    _ => return Err(BifError::BADARG),
                };
                let count = fields
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(2))
                    .ok_or(BifError::BADARG)?;
                count_ok(count, r.bytes.len() - r.at, input_complete)?;
                stack.push(Frame {
                    kind: FrameKind::Record { exported, fields },
                    left: count,
                    values: SmallVec::new(),
                    shapes: SmallVec::new(),
                });
                None
            }
            _ => return Err(BifError::BADARG),
        };
        if let Some((mut term, mut shape)) = result {
            loop {
                if let Some(Frame {
                    kind: FrameKind::Local { hash, term_start },
                    ..
                }) = stack.last()
                {
                    let hash = *hash;
                    let term_start = *term_start;
                    stack.pop();
                    if local_term_hash(&r.bytes[term_start..r.at]) != hash {
                        return Err(BifError::BADARG);
                    }
                    continue;
                }
                let Some(frame) = stack.last_mut() else {
                    return Ok(Some((term, r.at)));
                };
                accept_child(frame, term, shape)?;
                frame.left -= 1;
                if frame.left != 0 {
                    break;
                }
                (term, shape) = finish(stack.pop().unwrap(), &mut ctx)?;
            }
        }
    }
    Ok(None)
}

fn parse(bytes: &[u8], safe: bool, ctx: Option<&mut Ctx<'_>>) -> Result<(Term, usize), BifError> {
    let mut reader = Reader { bytes, at: 0 };
    let mut stack = SmallVec::new();
    match parse_step(&mut reader, &mut stack, safe, None, ctx, usize::MAX, true)? {
        Some(value) => Ok(value),
        None => Err(BifError::BADARG),
    }
}

/// Incremental ETF validator retained by `binary_to_term_trap/1`.
pub struct DecodeWalk<'a> {
    input: DecodeInput<'a>,
    plain: SmallVec<[u8; 128]>,
    validator_at: usize,
    decode_at: usize,
    stack: SmallVec<[Frame; 4]>,
    safe: bool,
    local_node: Option<(arinsal_term::Atom, u32)>,
    used: bool,
    compressed: bool,
    used_prefix: usize,
    input_size: usize,
    input_offset: usize,
    expected_plain: usize,
    decompressor: Option<Decompress>,
    inflate_done: bool,
    checked_root: Option<usize>,
    sizing: DecodedSizeWalk,
    heap_words: Option<usize>,
    reservation: Option<HeapReservationState>,
    size_done: bool,
    decode_started: bool,
}

impl<'a> DecodeWalk<'a> {
    /// Start decoding an ETF binary while borrowing a reference-counted input payload.
    pub fn new(args: &'a [Term]) -> Result<Self, BifError> {
        let opts = decode_options(args.get(1).copied())?;
        // SAFETY: the input binary owner is live and stable during the BIF call.
        let view = unsafe { args[0].binary_ref() }.ok_or(BifError::BADARG)?;
        if !view.bit_len().is_multiple_of(8) {
            return Err(BifError::BADARG);
        }
        let can_borrow = view.is_refc()
            && view.start_bit().is_multiple_of(8)
            && !arinsal_term::is_writable_binary(args[0]);
        let input = if can_borrow {
            let offset = view.start_bit() / 8;
            let len = view.bit_len() / 8;
            DecodeInput::Borrowed {
                bytes: &view.bytes()[offset..offset + len],
                term: args[0],
                offset,
                len,
            }
        } else {
            DecodeInput::Inline(bit_bytes(args[0])?.0)
        };
        let bytes = input.bytes();
        if bytes.first() != Some(&131) {
            return Err(BifError::BADARG);
        }
        let (plain, used_prefix, compressed, expected_plain, decompressor) =
            if bytes.get(1) == Some(&80) {
                if bytes.len() < 6 {
                    return Err(BifError::BADARG);
                }
                let size = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
                // Port of erts/emulator/beam/external.c:1770-1779 (binary2term_prepare),
                // OTP-29.1.1. ERTS validates oversized length claims by counting output in
                // 64 KiB chunks before allocating the uncompressed external term.
                if size > B2T_MAX_DIRECT_UNCOMPRESSED_SIZE
                    && compressed_uncompressed_size(&bytes[6..])? != size
                {
                    return Err(BifError::BADARG);
                }
                (SmallVec::new(), 6, true, size, Some(Decompress::new(true)))
            } else {
                (SmallVec::new(), 1, false, 0, None)
            };
        let input_size = bytes.len();
        Ok(Self {
            input,
            plain,
            validator_at: 0,
            decode_at: 0,
            stack: SmallVec::new(),
            safe: opts.safe,
            local_node: None,
            used: opts.used,
            compressed,
            used_prefix,
            input_size,
            input_offset: 0,
            expected_plain,
            decompressor,
            inflate_done: !compressed,
            checked_root: None,
            sizing: DecodedSizeWalk::new(),
            heap_words: None,
            reservation: None,
            size_done: false,
            decode_started: false,
        })
    }

    /// Configure this node's identity for external pid, port, and reference terms.
    pub fn set_local_node(&mut self, node: arinsal_term::Atom, creation: u32) {
        self.local_node = Some((node, creation));
    }

    /// Retain the refc input only when the decoder is moved into a trap context.
    pub fn into_owned(self) -> Result<DecodeWalk<'static>, BifError> {
        let Self {
            input,
            plain,
            validator_at,
            decode_at,
            stack,
            safe,
            local_node,
            used,
            compressed,
            used_prefix,
            input_size,
            input_offset,
            expected_plain,
            decompressor,
            inflate_done,
            checked_root,
            sizing,
            heap_words,
            reservation,
            size_done,
            decode_started,
        } = self;
        let input = match input {
            DecodeInput::Inline(bytes) => DecodeInput::Inline(bytes),
            DecodeInput::Refc { owner, offset, len } => DecodeInput::Refc { owner, offset, len },
            DecodeInput::Borrowed {
                term, offset, len, ..
            } => match binary_owner(term) {
                // `new` excluded active writable handles. The process can still expose an
                // immutable bitstring backed by a writable owner; pin it like the BIF argument
                // root held by erts across a trap.
                Some(BinaryOwner::Binary(owner)) => DecodeInput::Refc { owner, offset, len },
                _ => return Err(BifError::BADARG),
            },
        };
        Ok(DecodeWalk {
            input,
            plain,
            validator_at,
            decode_at,
            stack,
            safe,
            local_node,
            used,
            compressed,
            used_prefix,
            input_size,
            input_offset,
            expected_plain,
            decompressor,
            inflate_done,
            checked_root,
            sizing,
            heap_words,
            reservation,
            size_done,
            decode_started,
        })
    }

    fn inflate_more(&mut self, output_budget: usize) -> Result<usize, BifError> {
        if self.inflate_done {
            return Ok(0);
        }
        let remaining = self.expected_plain.saturating_sub(self.plain.len());
        let capacity = output_budget.max(1).min(remaining.saturating_add(1));
        let mut output = SmallVec::<[u8; 128]>::new();
        output.resize(capacity, 0);
        let input = &self.input.bytes()[6 + self.input_offset..];
        let flush = if input.is_empty() {
            FlushDecompress::Finish
        } else {
            FlushDecompress::None
        };
        let inflater = self.decompressor.as_mut().ok_or(BifError::BADARG)?;
        let before_in = inflater.total_in();
        let before_out = inflater.total_out();
        let status = inflater
            .decompress(input, &mut output, flush)
            .map_err(|_| BifError::BADARG)?;
        let consumed =
            usize::try_from(inflater.total_in() - before_in).map_err(|_| BifError::BADARG)?;
        let produced =
            usize::try_from(inflater.total_out() - before_out).map_err(|_| BifError::BADARG)?;
        self.input_offset = self.input_offset.saturating_add(consumed);
        if self.plain.len().saturating_add(produced) > self.expected_plain {
            return Err(BifError::BADARG);
        }
        self.plain.extend_from_slice(&output[..produced]);
        if status == Status::StreamEnd {
            self.inflate_done = true;
            self.used_prefix = 6 + self.input_offset;
            if self.plain.len() != self.expected_plain {
                return Err(BifError::BADARG);
            }
        } else if consumed == 0 && produced == 0 {
            return Err(BifError::BADARG);
        }
        Ok(produced)
    }

    fn plain_bytes(&self) -> &[u8] {
        if self.compressed {
            &self.plain
        } else {
            &self.input.bytes()[1..]
        }
    }

    /// Validate at most `byte_budget` ETF input bytes and report consumed bytes.
    pub fn step(
        &mut self,
        byte_budget: usize,
    ) -> Result<(Option<usize>, usize), (BifError, usize)> {
        let mut consumed = 0;
        if let Some(checked) = self.checked_root {
            while !self.inflate_done && consumed < byte_budget.max(1) {
                let produced = self
                    .inflate_more(byte_budget.saturating_sub(consumed))
                    .map_err(|error| (error, consumed))?;
                consumed += produced.max(1);
            }
            if self.inflate_done {
                if checked != self.expected_plain || self.plain_bytes().len() != checked {
                    return Err((BifError::BADARG, consumed));
                }
                return Ok((Some(checked), consumed));
            }
            return Ok((None, consumed));
        }
        while consumed < byte_budget.max(1) {
            let before = self.validator_at;
            // One dec_term loop when the plain text is complete. Compressed
            // chunks stay at one tag so inflate can refill the buffer.
            let tags = if self.compressed && !self.inflate_done {
                1
            } else {
                byte_budget.saturating_sub(consumed).max(1)
            };
            let (parsed, after) = {
                let bytes = if self.compressed {
                    &self.plain[..]
                } else {
                    &self.input.bytes()[1..]
                };
                let mut reader = Reader { bytes, at: before };
                let parsed = parse_step(
                    &mut reader,
                    &mut self.stack,
                    self.safe,
                    None,
                    None::<&mut Ctx<'_, crate::ProcessHeapHandle<'_>>>,
                    tags,
                    !self.compressed || self.inflate_done,
                );
                (parsed, reader.at)
            };
            self.validator_at = after;
            match parsed {
                Ok(Some((_, checked))) => {
                    consumed += self.validator_at - before;
                    if self.compressed && !self.inflate_done {
                        self.checked_root = Some(checked);
                        let produced = self
                            .inflate_more(byte_budget.saturating_sub(consumed))
                            .map_err(|error| (error, consumed))?;
                        consumed += produced.max(1);
                        continue;
                    }
                    if self.compressed && checked != self.plain_bytes().len() {
                        return Err((BifError::BADARG, consumed));
                    }
                    return Ok((Some(checked), consumed));
                }
                Ok(None) => consumed += self.validator_at - before,
                Err(BifError::Unsupported("incomplete ETF input")) => {
                    self.validator_at = before;
                    if !self.compressed || self.inflate_done {
                        return Err((BifError::BADARG, consumed));
                    }
                    let produced = self
                        .inflate_more(byte_budget.saturating_sub(consumed))
                        .map_err(|error| (error, consumed))?;
                    consumed += produced.max(1);
                }
                Err(error) => return Err((error, consumed + self.validator_at - before)),
            }
        }
        Ok((None, consumed))
    }

    /// Parse and build a bounded prefix into the supplied live process heap.
    pub fn step_into(
        &mut self,
        byte_budget: usize,
        ctx: &mut Ctx<'_>,
    ) -> Result<(Option<Term>, usize), (BifError, usize)> {
        let mut consumed = 0;
        if !self.size_done {
            let (checked, size_work) = self.size_step(byte_budget.max(1))?;
            consumed += size_work;
            let Some(_) = checked else {
                return Ok((None, consumed));
            };
            self.decode_at = 0;
            self.stack.clear();
            self.decode_started = true;
            if consumed >= byte_budget.max(1) {
                return Ok((None, consumed));
            }
        }
        if !self.decode_started {
            self.decode_at = 0;
            self.stack.clear();
            self.decode_started = true;
        }
        let Some(_heap_words) = self.heap_words else {
            return Err((BifError::BADARG, consumed));
        };
        let reservation = match self.reservation.take() {
            Some(state) => HeapReservation::resume(&mut ctx.heap, state),
            None => HeapReservation::new(&mut ctx.heap, _heap_words)
                .map_err(|error| (map_term_build_error(error), consumed))?,
        };
        let mut state = crate::BifState::default();
        let mut decode_ctx = Ctx::with_allocator(reservation, &mut state);
        let budget = byte_budget.max(1).saturating_sub(consumed);
        let mut decoded = 0;
        let parsed = loop {
            if decoded >= budget {
                break Ok(None);
            }
            let before = self.decode_at;
            let (parsed, after) = {
                let bytes = if self.compressed {
                    &self.plain[..]
                } else {
                    &self.input.bytes()[1..]
                };
                let mut reader = Reader { bytes, at: before };
                let parsed = parse_step(
                    &mut reader,
                    &mut self.stack,
                    self.safe,
                    self.local_node,
                    Some(&mut decode_ctx),
                    budget.saturating_sub(decoded).max(1),
                    true,
                );
                (parsed, reader.at)
            };
            self.decode_at = after;
            match parsed {
                Ok(Some((term, checked))) => {
                    decoded += self.decode_at - before;
                    if self.compressed && checked != self.plain_bytes().len() {
                        break Err((BifError::BADARG, decoded));
                    }
                    break Ok(Some((term, checked)));
                }
                Ok(None) => decoded += self.decode_at - before,
                Err(BifError::Unsupported("incomplete ETF input")) => {
                    self.decode_at = before;
                    break Err((BifError::BADARG, decoded));
                }
                Err(error) => break Err((error, decoded + self.decode_at - before)),
            }
        };
        let reservation = decode_ctx.into_allocator();
        match parsed {
            Ok(Some((term, checked))) => {
                drop(reservation);
                let value = self
                    .wrap_used(ctx, term, checked)
                    .map_err(|error| (error, consumed + decoded))?;
                Ok((Some(value), consumed + decoded))
            }
            Ok(None) => {
                self.reservation = Some(reservation.suspend());
                Ok((None, consumed + decoded))
            }
            Err((error, work)) => {
                drop(reservation);
                Err((error, consumed + work))
            }
        }
    }

    fn size_step(
        &mut self,
        byte_budget: usize,
    ) -> Result<(Option<usize>, usize), (BifError, usize)> {
        let mut consumed = 0;
        // Port of erts/emulator/beam/external.c (binary_to_term_int, B2TUncompressChunk to
        // B2TSizeInit), OTP-29.1.1: finish inflation before entering `decoded_size`.
        while self.compressed && !self.inflate_done && consumed < byte_budget {
            let produced = self
                .inflate_more(byte_budget.saturating_sub(consumed))
                .map_err(|error| (error, consumed))?;
            consumed += produced.max(1);
            if produced == 0 && !self.inflate_done {
                return Err((BifError::BADARG, consumed));
            }
        }
        if self.compressed && !self.inflate_done {
            return Ok((None, consumed));
        }
        while consumed < byte_budget {
            let before = (self.input_offset, self.plain_bytes().len());
            let input_complete = !self.compressed || self.inflate_done;
            let bytes = if self.compressed {
                &self.plain[..]
            } else {
                &self.input.bytes()[1..]
            };
            let scanned = self
                .sizing
                .step(
                    bytes,
                    byte_budget.saturating_sub(consumed),
                    input_complete,
                    local_term_hash,
                )
                .map_err(|error| (decode_size_error(error), consumed))?;
            consumed += scanned.1;
            if let Some((words, checked)) = scanned.0 {
                if self.compressed
                    && (checked != self.expected_plain || checked != self.plain_bytes().len())
                {
                    return Err((BifError::BADARG, consumed));
                }
                self.heap_words = Some(words);
                self.size_done = true;
                return Ok((Some(checked), consumed));
            }
            if consumed >= byte_budget {
                break;
            }
            if self.compressed && (self.input_offset, self.plain_bytes().len()) == before {
                return Err((BifError::BADARG, consumed));
            }
        }
        Ok((None, consumed))
    }

    fn wrap_used(&self, ctx: &mut Ctx<'_>, term: Term, checked: usize) -> Result<Term, BifError> {
        if self.used {
            let used = if self.compressed {
                self.used_prefix
            } else {
                self.used_prefix + checked
            };
            let size = integer(ctx, used)?;
            Ok(tuple_build(ctx, &[term, size]))
        } else {
            Ok(term)
        }
    }

    /// Decode the validated prefix into the current process heap.
    pub fn finish(&self, ctx: &mut Ctx<'_>, checked: usize) -> Result<Term, BifError> {
        let (term, _) =
            parse(&self.plain_bytes()[..checked], self.safe, Some(ctx)).map_err(decode_error)?;
        self.wrap_used(ctx, term, checked)
    }

    /// Return the original ETF byte length for reduction accounting.
    pub fn input_size(&self) -> usize {
        self.input_size
    }
}

// Port of erts/emulator/beam/external.c:1719-1741 (binary2term_uncomp_size), OTP-29.1.1.
fn compressed_uncompressed_size(input: &[u8]) -> Result<usize, BifError> {
    let mut decompressor = Decompress::new(true);
    let mut output = [0; 64 * 1024];
    loop {
        let consumed = usize::try_from(decompressor.total_in()).map_err(|_| BifError::BADARG)?;
        let before_out = decompressor.total_out();
        let status = decompressor
            .decompress(
                input.get(consumed..).ok_or(BifError::BADARG)?,
                &mut output,
                FlushDecompress::Finish,
            )
            .map_err(|_| BifError::BADARG)?;
        if status == Status::StreamEnd {
            return usize::try_from(decompressor.total_out()).map_err(|_| BifError::BADARG);
        }
        if decompressor.total_in() == consumed as u64 && decompressor.total_out() == before_out {
            return Err(BifError::BADARG);
        }
    }
}

fn binary_to_term(ctx: &mut Ctx<'_>, args: &[Term]) -> Term {
    match binary_to_term_result(ctx, args) {
        Ok(value) => value,
        Err(error) => ctx.fail(error),
    }
}

fn binary_to_term_result(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut decoder = DecodeWalk::new(args)?;
    ctx.charge_reductions(decoder.input_size());
    let (term, _) = decoder
        .step_into(usize::MAX, ctx)
        .map_err(|(error, _)| decode_error(error))?;
    term.ok_or(BifError::BADARG)
}

fn decode_error(error: BifError) -> BifError {
    match error {
        BifError::Unsupported(_) => BifError::BADARG,
        other => other,
    }
}

fn decode_size_error(_: arinsal_etf::DecodeError) -> BifError {
    BifError::BADARG
}

#[cfg(test)]
mod map_sort_tests {
    #[test]
    fn reports_encode_walk_layout() {
        use super::*;
        eprintln!(
            "EncodeWalk={} WStack={} EncodeCold={} BlockHashWalk={} EncodeOpts={} Compress={} out={} splits={} work={}",
            std::mem::size_of::<EncodeWalk>(),
            std::mem::size_of::<WStack>(),
            std::mem::size_of::<EncodeCold>(),
            std::mem::size_of::<BlockHashWalk>(),
            std::mem::size_of::<EncodeOpts>(),
            std::mem::size_of::<Option<Compress>>(),
            std::mem::size_of::<Vec<u8>>(),
            std::mem::size_of::<Vec<(usize, usize)>>(),
            std::mem::size_of::<Vec<Term>>(),
        );
    }

    use super::MapSort;
    use arinsal_term::Term;

    #[test]
    fn bottom_up_map_sort_runs_across_budget_boundaries() {
        let input = (0..33)
            .rev()
            .map(|key| (Term::small(key).unwrap(), Term::NIL))
            .collect();
        let mut sort = MapSort::new(input);
        while !sort.is_done() {
            sort.step(1);
        }
        let keys: Vec<_> = sort
            .finish()
            .into_iter()
            .map(|(key, _)| key.as_small().unwrap())
            .collect();
        assert_eq!(keys, (0..33).collect::<Vec<_>>());
    }
}

crate::word_bif_bodies_in!(word_bodies; term_to_binary, term_to_iovec, external_size, binary_to_term);
