//! ETF BIFs over live process heap terms.
// Port of erts/emulator/beam/external.c (external term sizing, encoding, and decoding), OTP-29.1.1.

use std::cmp::Ordering;
use std::io::Write;
use std::sync::OnceLock;

use arinsal_term::raw::{Cons, Tuple, term_at_pointer, term_from_bits};
use arinsal_term::{
    Atom, FunRef, HeapAlloc, Identity, RefcBinary, Term, TermBuilder, TermKind, atoms, cmp_exact,
    global_atoms,
};
use flate2::{Compress, Compression, FlushCompress, Status};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use smallvec::SmallVec;

use crate::BifError;
use crate::pure::Heap;

static LOCAL_NODE_HASH: OnceLock<u32> = OnceLock::new();

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
pub struct BlockHashWalk {
    a: u32,
    b: u32,
    c: u32,
    length: usize,
    cursor: usize,
    hash: Option<u32>,
}

impl BlockHashWalk {
    /// `erts_block_hash_init` over `length` bytes with the hash of this node as the seed, as
    /// `LOCAL_EXT` uses it.
    pub fn local(length: usize) -> Self {
        Self::new(length, local_node_hash())
    }

    /// The hash once `step` reported the end of the data.
    pub fn hash(&self) -> Option<u32> {
        self.hash
    }

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

    /// `erts_block_hash` with `budget` bytes: whether the data is done and the bytes hashed.
    pub fn step(&mut self, bytes: &[u8], budget: usize) -> (bool, usize) {
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
pub fn local_term_hash(bytes: &[u8]) -> u32 {
    block_hash(bytes, local_node_hash())
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
    cons: Cons<'static>,
) -> Result<Term, BifError> {
    let len_cnt = pop_stack_small(stack);
    let (head, tail) = cons.pair();
    if is_list_term(tail) {
        stack.push(stack_small(len_cnt + 1)?);
        push_term_task(stack, ENC_ONE_CONS, tail);
    } else {
        let len_at = pop_stack_small(stack);
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
fn external_string_prefix(mut term: Term, first: Cons<'static>) -> (usize, bool) {
    let mut len = 0usize;
    let mut first = Some(first);
    loop {
        let cell = match first.take() {
            Some(cell) => cell,
            None => match Cons::try_from(term) {
                Ok(cell) => cell,
                Err(_) => return (len, term == Term::NIL),
            },
        };
        // A small integer in 0..=255: the low four tag bits are 1111 and the value is above.
        let head = cell.head().word();
        if head & 15 != 15 || head >> 4 > 255 {
            return (len, false);
        }
        len += 1;
        if len > 0xffff {
            return (len, false);
        }
        term = cell.tail();
    }
}

fn exact_key_cmp(left: Term, right: Term) -> Ordering {
    // Port of erts/emulator/beam/external.c:3217 (CMP_TERM), OTP-29.1.1.
    cmp_exact(left, right)
}

enum FastEncodeKind<'h> {
    Small(i64),
    Atom(Atom),
    Nil,
    List(Cons<'h>),
    Tuple(Tuple<'h>),
    Rare(TermKind),
}

#[inline(always)]
// Port of tag_val_def dispatch in erts/emulator/beam/external.c
// (encode_size_struct_int / enc_term_int), OTP-29.1.1.
fn fast_encode_kind<'h>(term: Term) -> FastEncodeKind<'h> {
    let bits = term.word();
    match bits & 3 {
        1 => match Cons::try_from(term) {
            Ok(cons) => FastEncodeKind::List(cons),
            Err(_) => FastEncodeKind::Rare(term.classify()),
        },
        2 => match Tuple::try_from(term) {
            Ok(tuple) => FastEncodeKind::Tuple(tuple),
            Err(_) => FastEncodeKind::Rare(term.classify()),
        },
        3 if bits & 15 == 15 => FastEncodeKind::Small((bits as i64) >> 4),
        3 => match bits & 63 {
            11 => FastEncodeKind::Atom(Atom((bits >> 6) as u32)),
            0x3b => FastEncodeKind::Nil,
            _ => FastEncodeKind::Rare(term.classify()),
        },
        _ => FastEncodeKind::Rare(term.classify()),
    }
}

const WSTACK_INLINE: usize = 32;

/// The work stack of the encoder passes.
// Port of DECLARE_WSTACK / WSTACK_PUSH / WSTACK_POP in erts/emulator/beam/erl_term.h and
// global.h, OTP-29.1.1: a default-size array that lives in the frame of the pass, a heap
// overflow area, and `WSTACK_SAVE` / `WSTACK_RESTORE` to move the contents into the saved
// context (`EncodeWalk::work`) when the pass yields.
struct WStack {
    len: usize,
    inline: [u64; WSTACK_INLINE],
    spill: Vec<u64>,
}

impl WStack {
    #[inline(always)]
    fn new() -> Self {
        Self {
            len: 0,
            inline: [0; WSTACK_INLINE],
            spill: Vec::new(),
        }
    }

    /// `WSTACK_RESTORE`: take the words of a saved context.
    #[inline(always)]
    fn restore(&mut self, saved: &mut Vec<u64>) {
        if !saved.is_empty() {
            for word in saved.drain(..) {
                self.push(word);
            }
        }
    }

    #[inline(always)]
    fn push(&mut self, word: u64) {
        if self.len < WSTACK_INLINE {
            self.inline[self.len] = word;
        } else {
            self.push_spilled(word);
        }
        self.len += 1;
    }

    // `WSTACK_EXPAND`: the overflow area grows by doubling from a first block.
    #[cold]
    #[inline(never)]
    fn push_spilled(&mut self, word: u64) {
        if self.spill.capacity() == 0 {
            self.spill.reserve(256);
        }
        self.spill.push(word);
    }

    #[inline(always)]
    fn pop(&mut self) -> Option<u64> {
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
    fn pop_word(&mut self) -> u64 {
        debug_assert_ne!(self.len, 0);
        self.len -= 1;
        if self.len < WSTACK_INLINE {
            self.inline[self.len]
        } else {
            self.spill.pop().expect("WSTACK spill is nonempty")
        }
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// `WSTACK_SAVE`: move the contents, bottom first, into `saved`.
    fn save(&mut self, saved: &mut Vec<u64>) {
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

// Array kinds of TERM_ARRAY_OP: tuple tasks carry an Eterm* cursor plus a count like erts;
// other Rust arrays retain their container term and kind with the count.
const ARRAY_TUPLE: u64 = 0;
const ARRAY_FLAT_KEYS: u64 = 1;
const ARRAY_FLAT_VALUES: u64 = 2;
const ARRAY_FUN_ENV: u64 = 3;
const ARRAY_RECORD: u64 = 4;

const fn size_op(code: u64) -> u64 {
    Term::catch(code).word()
}

// Encode pass commands are the raw operation values used by enc_term_int.
const ENC_TERM_CODE: u64 = 0;
const ENC_ONE_CONS_CODE: u64 = 1;
const ENC_PATCH_FUN_SIZE_CODE: u64 = 2;
const ENC_BIN_COPY_CODE: u64 = 3;
const ENC_MAP_PAIR_CODE: u64 = 4;
const ENC_HASHMAP_NODE_CODE: u64 = 5;
const ENC_START_SORTING_MAP_CODE: u64 = 7;
const ENC_LAST_ARRAY_ELEMENT: u64 = 10;

const ENC_TERM: u64 = stack_command(ENC_TERM_CODE as i64);
const ENC_ONE_CONS: u64 = stack_command(ENC_ONE_CONS_CODE as i64);
const ENC_PATCH_FUN_SIZE: u64 = stack_command(ENC_PATCH_FUN_SIZE_CODE as i64);
const ENC_BIN_COPY: u64 = stack_command(ENC_BIN_COPY_CODE as i64);
const ENC_HASHMAP_NODE: u64 = stack_command(ENC_HASHMAP_NODE_CODE as i64);
const ENC_START_SORTING_MAP: u64 = stack_command(ENC_START_SORTING_MAP_CODE as i64);

const fn stack_command(code: i64) -> u64 {
    match Term::small(code) {
        Some(term) => term.word(),
        None => panic!("ETF stack command must fit a small integer"),
    }
}

#[inline(always)]
fn is_list_term(term: Term) -> bool {
    term.word() & 3 == 1
}

// Port of WSTACK_PUSH2 in erts/emulator/beam/external.c, OTP-29.1.1.
#[inline(always)]
fn push_term_task(stack: &mut WStack, command: u64, term: Term) {
    if command & 63 == 0x1b {
        stack.push(term.word());
        stack.push(command);
    } else {
        stack.push(command);
        stack.push(term.word());
    }
}

#[inline(always)]
// Port of WSTACK_PUSH2 in erts/emulator/beam/external.c (enc_term_int tuple array), OTP-29.1.1.
fn push_tuple_pointer_task(stack: &mut WStack, command: u64, pointer: u64) {
    stack.push(command);
    stack.push(pointer);
}

#[inline(always)]
fn push_flatmap_task(
    stack: &mut WStack,
    container: Term,
    remaining: usize,
) -> Result<(), BifError> {
    stack.push(container.word());
    stack.push(stack_command(ENC_MAP_PAIR_CODE as i64));
    stack.push(stack_small(remaining)?);
    Ok(())
}

// Port of the `WSTACK_PUSH` calls that push a node without an operation word.
#[inline(always)]
fn push_task(stack: &mut WStack, command: Option<u64>, term: Term) {
    if let Some(command) = command {
        if command & 63 == 0x1b {
            stack.push(term.word());
            stack.push(command);
        } else {
            stack.push(command);
            stack.push(term.word());
        }
    } else {
        stack.push(term.word());
    }
}

#[inline(always)]
fn stack_small(value: usize) -> Result<u64, BifError> {
    u64::try_from(value).map_err(|_| BifError::SystemLimit)
}

// Port of the saved integer WSTACK words in erts/emulator/beam/external.c (enc_term_int).
#[inline(always)]
fn pop_stack_small(stack: &mut WStack) -> usize {
    usize::try_from(stack.pop_word()).expect("WSTACK integer fits usize")
}

// Port of TERM_ARRAY_OP(N) pushes in erts/emulator/beam/external.c
// (encode_size_struct_int), OTP-29.1.1: `remaining` elements still to read.
#[inline(always)]
fn push_size_array(stack: &mut WStack, container: Term, remaining: usize, kind: u64) {
    stack.push(container.word());
    stack.push(size_op(SIZE_ARRAY + (((remaining as u64) << 3) | kind)));
}

#[inline(always)]
fn push_size_tuple_array(stack: &mut WStack, pointer: u64, remaining: usize) {
    stack.push(pointer);
    stack.push(size_op(
        SIZE_ARRAY + ((remaining as u64) << 3) + ARRAY_TUPLE,
    ));
}

/// Element `len - remaining` of the array a TERM_ARRAY_OP walks.
#[inline(always)]
fn size_array_element(kind: u64, container: Term, remaining: usize) -> Result<Term, BifError> {
    match kind {
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
    if word & 63 != 0x1b {
        return Ok(Some(term_from_bits(word)));
    }
    let code = word >> 6;
    if code == SIZE_LIST_TAIL {
        let tail = term_from_bits(stack.pop_word());
        if is_list_term(tail) {
            let (head, rest) = Cons::try_from(tail).map_err(|_| BifError::BADARG)?.pair();
            push_term_task(stack, size_op(SIZE_LIST_TAIL), rest);
            Ok(Some(head))
        } else {
            Ok(Some(tail))
        }
    } else if code == SIZE_HASHMAP_NODE {
        let node = term_from_bits(stack.pop_word());
        Ok(Some(push_hashmap_node_tasks(
            stack,
            node,
            Some(size_op(SIZE_HASHMAP_NODE)),
            None,
        )?))
    } else {
        let spec = code - SIZE_ARRAY;
        let remaining = (spec >> 3) as usize;
        let obj = if spec & 7 == ARRAY_TUPLE {
            let pointer = stack.pop_word();
            let obj = term_at_pointer(pointer);
            if remaining > 1 {
                push_size_tuple_array(stack, pointer + 8, remaining - 1);
            }
            obj
        } else {
            let container = term_from_bits(stack.pop_word());
            let obj = size_array_element(spec & 7, container, remaining)?;
            if remaining > 1 {
                push_term_task(stack, size_op(code - 8), container);
            }
            obj
        };
        Ok(Some(obj))
    }
}

// Port of erts/emulator/beam/external.c:5812-5825 (HASHMAP_NODE_OP), OTP-29.1.1.
#[inline(always)]
fn push_hashmap_root_tasks(
    stack: &mut WStack,
    map: Term,
    node_command: u64,
    term_command: Option<u64>,
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
    node_command: Option<u64>,
    value_command: Option<u64>,
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
        match fast_encode_kind(obj) {
            FastEncodeKind::Small(value) => add!(small_size(value)),
            FastEncodeKind::Atom(atom) => add!(atom_size_in(table, atom, minor)?),
            FastEncodeKind::Nil => add!(1),
            FastEncodeKind::List(cons) => {
                // Port of erts/emulator/beam/external.c (is_external_string), OTP-29.1.1.
                let (len, is_string) = external_string_prefix(obj, cons);
                work += len / 2;
                if is_string {
                    add!(3 + len);
                } else {
                    add!(5);
                    let (head, rest) = cons.pair();
                    push_term_task(stack, size_op(SIZE_LIST_TAIL), rest);
                    obj = head;
                    continue;
                }
            }
            FastEncodeKind::Tuple(tuple) => {
                let arity = tuple.arity();
                add!(if arity <= 255 { 2 } else { 5 });
                if arity > 0 {
                    if arity > 1 {
                        let pointer = tuple.element_pointer(1).ok_or(BifError::BADARG)?;
                        push_size_tuple_array(stack, pointer, arity - 1);
                    }
                    obj = tuple.get(0).ok_or(BifError::BADARG)?;
                    continue;
                }
            }
            FastEncodeKind::Rare(TermKind::Number) => {
                if obj.header().is_some_and(|header| header & 63 == 0x18) {
                    add!(if minor == 0 { 32 } else { 9 });
                } else {
                    add!(bignum_size(obj)?);
                }
            }
            FastEncodeKind::Rare(TermKind::Map) => {
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
            FastEncodeKind::Rare(TermKind::Bitstring) => {
                let bits = crate::pure::bitstring_bit_len(obj)?;
                let len = bits.div_ceil(8);
                let header: usize = if bits.is_multiple_of(8) { 5 } else { 6 };
                add!(header.checked_add(len).ok_or(BifError::SystemLimit)?);
            }
            FastEncodeKind::Rare(TermKind::Pid | TermKind::Port | TermKind::Ref) => {
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
            FastEncodeKind::Rare(TermKind::Fun) => {
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
                        stack.push(entry.pid.word());
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
            FastEncodeKind::Rare(TermKind::Record) => {
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
            FastEncodeKind::Rare(_) => return Err(BifError::Unsupported("ETF representation")),
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
    work: Vec<u64>,
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
            if consumed + 1 >= budget && !(free_first && (cur.is_some() || !stack.is_empty())) {
                break;
            }
            let term = if let Some(term) = cur.take() {
                term
            } else {
                // outer_loop
                let Some(object_word) = stack.pop() else {
                    break;
                };
                let command = stack.pop_word();
                let code = command >> 4;
                if code == ENC_TERM_CODE {
                    term_from_bits(object_word)
                } else if code == ENC_ONE_CONS_CODE {
                    let list = term_from_bits(object_word);
                    let cons = Cons::try_from(list).map_err(|_| BifError::BADARG)?;
                    encode_one_cons(&mut stack, out, cons)?
                } else if code == ENC_MAP_PAIR_CODE {
                    let remaining = usize::try_from(object_word).map_err(|_| BifError::BADARG)?;
                    let container = term_from_bits(stack.pop_word());
                    let (key, value) = flatmap_pair(container, remaining)?;
                    if remaining > 1 {
                        push_flatmap_task(&mut stack, container, remaining - 1)?;
                    }
                    push_term_task(&mut stack, ENC_TERM, value);
                    key
                } else if code >= ENC_LAST_ARRAY_ELEMENT {
                    // ENC_LAST_ARRAY_ELEMENT+N: a tuple element pointer and count.
                    let remaining = code - ENC_LAST_ARRAY_ELEMENT + 1;
                    let pointer = object_word;
                    let element = term_at_pointer(pointer);
                    if remaining > 1 {
                        push_tuple_pointer_task(
                            &mut stack,
                            stack_command((code - 1) as i64),
                            pointer + 8,
                        );
                    }
                    element
                } else if code == ENC_PATCH_FUN_SIZE_CODE {
                    consumed += 1;
                    let at = usize::try_from(object_word).map_err(|_| BifError::BADARG)?;
                    let size = u32::try_from(out.len() - at).map_err(|_| BifError::SystemLimit)?;
                    out.patch(at, &size.to_be_bytes());
                    continue;
                } else if code == ENC_BIN_COPY_CODE {
                    let term = term_from_bits(object_word);
                    let bits = pop_stack_small(&mut stack);
                    let copied = pop_stack_small(&mut stack);
                    let start = pop_stack_small(&mut stack);
                    // Port of erts/emulator/beam/external.c:3368 (ENC_BIN_COPY), OTP-29.1.1.
                    let len = bits.div_ceil(8);
                    let available = budget.saturating_sub(consumed);
                    if available == 0 {
                        stack.push(stack_small(start)?);
                        stack.push(stack_small(copied)?);
                        stack.push(stack_small(bits)?);
                        stack.push(ENC_BIN_COPY);
                        stack.push(term.word());
                        break;
                    }
                    let amount = len.saturating_sub(copied).min(available);
                    let bit_count = (amount * 8).min(bits.saturating_sub(copied * 8));
                    out.write_bitstring(term, copied * 8, bit_count)?;
                    consumed += amount;
                    if copied + amount < len {
                        stack.push(stack_small(start)?);
                        stack.push(stack_small(copied + amount)?);
                        stack.push(stack_small(bits)?);
                        stack.push(ENC_BIN_COPY);
                        stack.push(term.word());
                    } else {
                        if !bits.is_multiple_of(8) {
                            out.mask_last(0xff << (8 - bits % 8));
                        }
                        if len > 64 && record_splits {
                            self.cold().splits.push((start, out.len()));
                        }
                    }
                    continue;
                } else if code == ENC_HASHMAP_NODE_CODE {
                    let node = term_from_bits(object_word);
                    cur = Some(push_hashmap_node_tasks(
                        &mut stack,
                        node,
                        Some(ENC_HASHMAP_NODE),
                        Some(ENC_TERM),
                    )?);
                    continue;
                } else if code == ENC_START_SORTING_MAP_CODE {
                    debug_assert_eq!(object_word, Term::NON_VALUE.word());
                    let mut sorting = self.cold().map_sort.take().ok_or(BifError::BADARG)?;
                    let work_budget = budget.saturating_sub(consumed).max(1);
                    consumed += sorting.step(work_budget);
                    if sorting.is_done() {
                        push_sorted_map_tasks(&mut stack, (*sorting).finish());
                    } else {
                        self.cold().map_sort = Some(sorting);
                        stack.push(ENC_START_SORTING_MAP);
                        stack.push(Term::NON_VALUE.word());
                    }
                    continue;
                } else {
                    return Err(BifError::BADARG);
                }
            };
            if !std::mem::take(&mut free_first) {
                consumed += 1;
            }
            match fast_encode_kind(term) {
                FastEncodeKind::Small(n) => write_small(out, n),
                FastEncodeKind::Atom(atom) => {
                    atom_bytes_in(table, out, atom, opts.minor)?;
                }
                FastEncodeKind::Nil => out.push(106),
                FastEncodeKind::Rare(TermKind::Number) => {
                    if let Some(header) = term.header() {
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
                FastEncodeKind::List(cons) => {
                    // Port of erts/emulator/beam/external.c:3703 (LIST_DEF), OTP-29.1.1.
                    let (len, is_string) = external_string_prefix(term, cons);
                    if is_string {
                        out.push(107);
                        out.extend_from_slice(&(len as u16).to_be_bytes());
                        let first = cons.head().as_small().ok_or(BifError::BADARG)?;
                        out.push(first as u8);
                        let mut cursor = cons.tail();
                        for _ in 1..len {
                            // external_string_prefix already walked these cons cells.
                            let cell = Cons::try_from(cursor).map_err(|_| BifError::BADARG)?;
                            out.push(cell.head().as_small().ok_or(BifError::BADARG)? as u8);
                            cursor = cell.tail();
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
                        cur = Some(encode_one_cons(&mut stack, out, cons)?);
                    }
                }
                FastEncodeKind::Tuple(tuple) => {
                    let arity = tuple.arity();
                    if arity <= 255 {
                        out.extend_from_slice(&[104, arity as u8]);
                    } else {
                        out.push(105);
                        out.extend_from_slice(&(arity as u32).to_be_bytes());
                    }
                    if arity > 0 {
                        // WSTACK_PUSH2(s, ENC_LAST_ARRAY_ELEMENT+i-1, ptr)
                        let pointer = tuple.element_pointer(0).ok_or(BifError::BADARG)?;
                        push_tuple_pointer_task(
                            &mut stack,
                            stack_command((ENC_LAST_ARRAY_ELEMENT + arity as u64 - 1) as i64),
                            pointer,
                        );
                    }
                }
                FastEncodeKind::Rare(TermKind::Map) => {
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
                                stack.push(Term::NON_VALUE.word());
                            } else if len > 0 {
                                // WSTACK_PUSH4(s, kptr, vptr, ENC_MAP_PAIR, size)
                                push_flatmap_task(&mut stack, term, len)?;
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
                                    stack.push(Term::NON_VALUE.word());
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
                FastEncodeKind::Rare(TermKind::Bitstring) => {
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
                            stack.push(ENC_BIN_COPY);
                            stack.push(term.word());
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
                FastEncodeKind::Rare(TermKind::Pid | TermKind::Port | TermKind::Ref) => {
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
                FastEncodeKind::Rare(TermKind::Fun) => match fun_of(term)? {
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
                        stack.push(ENC_PATCH_FUN_SIZE);
                        stack.push(stack_small(at)?);
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
                FastEncodeKind::Rare(TermKind::Record) => {
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
                FastEncodeKind::Rare(_) => {
                    return Err(BifError::Unsupported("ETF representation"));
                }
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
