//! ETF BIFs over live process heap terms.
// Port of erts/emulator/beam/external.c (external term sizing, encoding, and decoding), OTP-29.1.1.

use std::cmp::Ordering;
use std::io::Write;
use std::sync::{Arc, OnceLock};

use arinsal_term::{
    Atom, ExportEntry, FunEntry, FunRef, HeapAlloc, Identity, Node, Term, TermBuilder, TermKind,
    atoms, cmp_exact, global_atoms, writable_finalize, writable_resize_private,
};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use num_bigint::{BigInt, Sign};
use num_traits::ToPrimitive;
use smallvec::{SmallVec, smallvec};

use crate::pure::{Heap, integer, make_list, tuple_build};
use crate::{BifError, Ctx};

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
        ("erlang", "term_to_binary", 1 | 2) => v.entry::<bodies::term_to_binary>(),
        ("erlang", "term_to_iovec", 1 | 2) => v.entry::<bodies::term_to_iovec>(),
        ("erlang", "external_size", 1 | 2) => v.entry::<bodies::external_size>(),
        ("erlang", "binary_to_term", 1 | 2) => v.entry::<bodies::binary_to_term>(),
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
        if let Some(slot) = self.bytes.get_mut(self.position) {
            *slot = byte;
        } else {
            self.failed = true;
        }
        self.position = self.position.saturating_add(1);
    }

    fn extend_from_slice(&mut self, bytes: &[u8]) {
        let end = self.position.saturating_add(bytes.len());
        if let Some(destination) = self.bytes.get_mut(self.position..end) {
            destination.copy_from_slice(bytes);
        } else {
            self.failed = true;
            if let Some(destination) = self.bytes.get_mut(self.position..) {
                let copied = destination.len().min(bytes.len());
                destination[..copied].copy_from_slice(&bytes[..copied]);
            }
        }
        self.position = end;
    }

    fn extend_zeroed(&mut self, len: usize) {
        let end = self.position.saturating_add(len);
        if let Some(destination) = self.bytes.get_mut(self.position..end) {
            destination.fill(0);
        } else {
            self.failed = true;
            if let Some(destination) = self.bytes.get_mut(self.position..) {
                destination.fill(0);
            }
        }
        self.position = end;
    }

    fn patch(&mut self, at: usize, bytes: &[u8]) {
        if let Some(destination) = self.bytes.get_mut(at..at.saturating_add(bytes.len())) {
            destination.copy_from_slice(bytes);
        } else {
            self.failed = true;
        }
    }

    fn mask_last(&mut self, mask: u8) {
        if let Some(last) = self
            .position
            .checked_sub(1)
            .and_then(|at| self.bytes.get_mut(at))
        {
            *last &= mask;
        } else {
            self.failed = true;
        }
    }

    fn slice(&self, range: std::ops::Range<usize>) -> &[u8] {
        self.bytes.get(range).unwrap_or(&[])
    }

    fn slice_mut(&mut self, range: std::ops::Range<usize>) -> &mut [u8] {
        self.bytes.get_mut(range).unwrap_or(&mut [])
    }

    fn failed(&self) -> bool {
        self.failed
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
    let table = global_atoms();
    let name = table.text(atom).ok_or(BifError::BADARG)?;
    if minor <= 1
        && let Some(chars) = table.latin1_char_count(atom)
    {
        out.push(100);
        out.extend_from_slice(&(chars as u16).to_be_bytes());
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
        out.push(119);
        out.push(bytes.len() as u8);
    } else {
        out.push(118);
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(bytes);
    Ok(())
}

fn atom_term(out: &mut impl ByteOutput, term: Term, minor: u8) -> Result<(), BifError> {
    atom_bytes(out, term.as_atom().ok_or(BifError::BADARG)?, minor)
}

// Port of erts/emulator/beam/external.c:encode_atom_size, OTP-29.1.1.
fn atom_size(atom: Atom, minor: u8) -> Result<usize, BifError> {
    let table = global_atoms();
    let name = table.text(atom).ok_or(BifError::BADARG)?;
    let size = if minor <= 1
        && let Some(chars) = table.latin1_char_count(atom)
    {
        3 + chars
    } else if name.len() <= 255 {
        2 + name.len()
    } else {
        3 + name.len()
    };
    Ok(size)
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

// Port of erts/emulator/beam/external.c (is_external_string), OTP-29.1.1.
fn external_string_len(mut term: Term) -> Result<Option<usize>, BifError> {
    let mut len = 0usize;
    while term.classify() == TermKind::List {
        // SAFETY: the list cell remains live for the duration of this BIF.
        let (head, tail) = unsafe { term.cons_ref() }.ok_or(BifError::BADARG)?;
        if head.as_small().filter(|n| (0..=255).contains(n)).is_none() || len == 0xffff {
            return Ok(None);
        }
        len += 1;
        term = tail;
    }
    Ok((term == Term::NIL).then_some(len))
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
    while term.classify() == TermKind::List {
        let Ok((head, tail)) = crate::pure::iolist_cons(term) else {
            return (len, false);
        };
        if head.as_small().filter(|n| (0..=255).contains(n)).is_none() {
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

enum Work {
    Term(Term),
    PatchFun(usize),
    /// One cons of a `LIST_EXT`, length patched when the tail is not a list.
    /// Port of erts/emulator/beam/external.c:3328 (ENC_ONE_CONS), OTP-29.1.1.
    OneCons {
        list: Term,
        len_at: usize,
        len: u32,
    },
    BinaryCopy {
        term: Term,
        bits: usize,
        copied: usize,
        start: usize,
    },
    MapEntries(MapEntries),
    MapGather {
        entries: MapEntries,
        pairs: Vec<(Term, Term)>,
    },
    MapSort(MapSort),
}

struct MapEntries {
    size: usize,
    entries: MapEntryIter,
}

// Keeping the reverse iterator inline avoids one heap allocation per map.
#[allow(clippy::large_enum_variant)]
enum MapEntryIter {
    Flat {
        keys: arinsal_maps::FlatMapProjection,
        values: arinsal_maps::FlatMapProjection,
    },
    Hash(arinsal_term::MapReverseIter),
}

impl MapEntries {
    // Port of erts/emulator/beam/external.c:3745-3822 (MAP_DEF), OTP-29.1.1.
    fn new(map: Term) -> Result<Self, BifError> {
        let checked = arinsal_maps::checked_map(map).map_err(|_| BifError::BADARG)?;
        let size = checked.size();
        let entries = match checked.kind() {
            arinsal_maps::CheckedMapKind::Flatmap(flat) => MapEntryIter::Flat {
                keys: arinsal_maps::flatmap_projection(flat, true),
                values: arinsal_maps::flatmap_projection(flat, false),
            },
            arinsal_maps::CheckedMapKind::Hashmap(_) => {
                MapEntryIter::Hash(arinsal_term::MapReverseIter::new(map).ok_or(BifError::BADARG)?)
            }
        };
        Ok(Self { size, entries })
    }
}

impl Iterator for MapEntries {
    type Item = (Term, Term);

    // Port of erts/emulator/beam/external.c:3745-3822 (MAP_DEF), OTP-29.1.1.
    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.entries {
            MapEntryIter::Flat { keys, values } => Some((keys.next()?, values.next()?)),
            MapEntryIter::Hash(iter) => iter.next(),
        }
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

fn push_map_terms(work: &mut SmallVec<[Work; 4]>, pairs: Vec<(Term, Term)>) {
    for (key, value) in pairs.into_iter().rev() {
        work.push(Work::Term(value));
        work.push(Work::Term(key));
    }
}

type EncodedWithSplits = (Vec<u8>, Vec<(usize, usize)>);

/// Incremental ETF encoder used by the VM's trapping `term_to_binary` path.
pub struct EncodeWalk {
    opts: EncodeOpts,
    out: SmallVec<[u8; 64]>,
    splits: SmallVec<[(usize, usize); 4]>,
    work: SmallVec<[Work; 4]>,
    size_work: SmallVec<[SizeItem; 4]>,
    encoded_size: usize,
    written: usize,
    direct_started: bool,
    local_hash: Option<BlockHashWalk>,
    sized: bool,
    free_first: bool,
    iovec: bool,
    compressor: Option<Compress>,
    compression_finished: bool,
}

/// A pending visit of the size pass.
// Port of erts/emulator/beam/external.c (encode_size_struct_int), OTP-29.1.1.
// Keep HAMT traversal state inline in the saved size stack, as the OTP WStack does.
#[allow(clippy::large_enum_variant)]
enum SizeItem {
    Term(Term),
    Tail(Term),
    Map(MapEntries),
}

impl EncodeWalk {
    /// Empty state used after the source term has been fully encoded.
    pub fn completed() -> Self {
        Self {
            opts: EncodeOpts::default(),
            out: SmallVec::new(),
            splits: SmallVec::new(),
            work: SmallVec::new(),
            size_work: SmallVec::new(),
            encoded_size: 0,
            written: 0,
            direct_started: false,
            local_hash: None,
            sized: true,
            free_first: false,
            iovec: false,
            compressor: None,
            compression_finished: false,
        }
    }

    /// Begin encoding a `term_to_binary/1,2` argument vector.
    pub fn new(args: &[Term]) -> Result<Self, BifError> {
        let opts = options(args.get(1).copied())?;
        Ok(Self::start(args[0], opts))
    }

    fn start(term: Term, opts: EncodeOpts) -> Self {
        let mut out = smallvec![131];
        let mut encoded_size = 1;
        if opts.local {
            // Port of erts/emulator/beam/external.c:3305 (encode LOCAL_EXT), OTP-29.1.1.
            out.extend_from_slice(&[121, 0, 0, 0, 0]);
            encoded_size += 5;
        }
        Self {
            opts,
            out,
            splits: SmallVec::new(),
            work: smallvec![Work::Term(term)],
            size_work: smallvec![SizeItem::Term(term)],
            encoded_size,
            written: 0,
            direct_started: false,
            local_hash: None,
            sized: false,
            free_first: true,
            iovec: false,
            compressor: None,
            compression_finished: false,
        }
    }

    /// Mark the walk as `term_to_iovec`, which references large aligned binaries in place.
    pub fn set_iovec(&mut self, iovec: bool) {
        self.iovec = iovec;
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

    fn add_size(&mut self, size: usize) -> Result<(), BifError> {
        self.encoded_size = self
            .encoded_size
            .checked_add(size)
            .ok_or(BifError::SystemLimit)?;
        Ok(())
    }

    /// Count the yield counts of the size pass, at most `budget - 1` of them.
    // Port of erts/emulator/beam/external.c (encode_size_struct_int), OTP-29.1.1.
    fn size_step(&mut self, budget: usize, consumed: &mut usize) -> Result<bool, BifError> {
        while let Some(item) = self.size_work.pop() {
            if *consumed + 1 >= budget {
                self.size_work.push(item);
                return Ok(false);
            }
            *consumed += 1;
            let term = match item {
                SizeItem::Term(term) => term,
                SizeItem::Tail(tail) => {
                    if tail.classify() == TermKind::List {
                        let (head, rest) = crate::pure::iolist_cons(tail)?;
                        self.size_work.push(SizeItem::Tail(rest));
                        head
                    } else {
                        tail
                    }
                }
                SizeItem::Map(entries) => {
                    for (key, value) in entries {
                        self.size_work.push(SizeItem::Term(key));
                        self.size_work.push(SizeItem::Term(value));
                    }
                    continue;
                }
            };
            match term.classify() {
                TermKind::Number => {
                    let size = if let Some(value) = term.as_small() {
                        small_size(value)
                    } else if term.header().is_some_and(|header| header & 63 == 0x18) {
                        if self.opts.minor == 0 { 32 } else { 9 }
                    } else {
                        bignum_size(term)?
                    };
                    self.add_size(size)?;
                }
                TermKind::Atom => self.add_size(atom_size(
                    term.as_atom().ok_or(BifError::BADARG)?,
                    self.opts.minor,
                )?)?,
                TermKind::Nil => self.add_size(1)?,
                TermKind::List => {
                    *consumed += external_string_prefix(term).0 / 2;
                    if let Some(len) = external_string_len(term)? {
                        self.add_size(3 + len)?;
                    } else {
                        self.add_size(5)?;
                        let (head, rest) = crate::pure::iolist_cons(term)?;
                        self.size_work.push(SizeItem::Tail(rest));
                        self.size_work.push(SizeItem::Term(head));
                    }
                }
                TermKind::Tuple => {
                    let arity = crate::pure::tuple_arity(term)?;
                    self.add_size(if arity <= 255 { 2 } else { 5 })?;
                    for index in (0..arity).rev() {
                        self.size_work
                            .push(SizeItem::Term(crate::pure::tuple_element(term, index)?));
                    }
                }
                TermKind::Map => {
                    let entries = MapEntries::new(term)?;
                    let size = entries.size;
                    self.add_size(5)?;
                    if size > 0 {
                        self.size_work.push(SizeItem::Map(entries));
                    }
                }
                TermKind::Bitstring => {
                    let bits = crate::pure::bitstring_bit_len(term)?;
                    let len = bits.div_ceil(8);
                    let header: usize = if bits.is_multiple_of(8) { 5 } else { 6 };
                    self.add_size(header.checked_add(len).ok_or(BifError::SystemLimit)?)?;
                }
                TermKind::Pid | TermKind::Port | TermKind::Ref => {
                    // Port of erts/emulator/beam/external.c:5613-5636 (REF_DEF sizing), OTP-29.1.1.
                    let identity = term.identity().ok_or(BifError::BADARG)?;
                    let node_size = if self.opts.local {
                        1
                    } else {
                        atom_size(
                            match identity {
                                Identity::Pid { node, .. }
                                | Identity::Port { node, .. }
                                | Identity::Ref { node, .. } => node,
                            },
                            self.opts.minor,
                        )?
                    };
                    let size = match identity {
                        Identity::Pid { .. } => 1 + node_size + 12,
                        Identity::Port { .. } => 1 + node_size + 12,
                        Identity::Ref { ids, .. } => 1 + 2 + node_size + 4 + 4 * ids.len(),
                    };
                    self.add_size(size)?;
                }
                TermKind::Fun => {
                    let fun = fun_of(term)?;
                    match &fun {
                        FunRef::Export { entry } => {
                            self.add_size(
                                1 + atom_size(entry.module, self.opts.minor)?
                                    + atom_size(entry.function, self.opts.minor)?
                                    + small_size(i64::from(entry.arity)),
                            )?;
                        }
                        FunRef::Local { entry, .. } => {
                            self.add_size(
                                1 + 4
                                    + 1
                                    + 16
                                    + 4
                                    + 4
                                    + atom_size(entry.module, self.opts.minor)?
                                    + small_size(i64::from(entry.old_index))
                                    + small_size(i64::from(entry.old_uniq)),
                            )?;
                            self.size_work.push(SizeItem::Term(entry.pid));
                            for index in (0..fun.num_free()).rev() {
                                self.size_work
                                    .push(SizeItem::Term(fun.free(index).ok_or(BifError::BADARG)?));
                            }
                        }
                    }
                }
                TermKind::Record => {
                    let record = record_of(term)?;
                    let mut size = 1
                        + 4
                        + 1
                        + atom_size(record.module(), self.opts.minor)?
                        + atom_size(record.name(), self.opts.minor)?;
                    for index in (0..record.len()).rev() {
                        let sorted = record.sorted_index(index).ok_or(BifError::BADARG)?;
                        size = size
                            .checked_add(atom_size(
                                record.key(sorted).ok_or(BifError::BADARG)?,
                                self.opts.minor,
                            )?)
                            .ok_or(BifError::SystemLimit)?;
                        self.size_work.push(SizeItem::Term(
                            record.value(sorted).ok_or(BifError::BADARG)?,
                        ));
                    }
                    self.add_size(size)?;
                }
                _ => return Err(BifError::Unsupported("ETF representation")),
            }
        }
        Ok(true)
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
        let mut output = std::mem::take(&mut self.out);
        let result = self.step_with_output(budget, &mut output, 0);
        self.out = output;
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
            self.out.clear();
        }
        let mut writer = OutputSlice::new(output, self.written);
        let (mut done, used) = self.step_with_output(budget, &mut writer, size_work)?;
        self.written = writer.len();
        if writer.failed() {
            return Err(BifError::SystemLimit);
        }
        if done && self.opts.local {
            let hash_walk = self
                .local_hash
                .get_or_insert_with(|| BlockHashWalk::new(self.written - 6, local_node_hash()));
            let remaining_work = budget.saturating_sub(used);
            let hash_budget = (remaining_work / 32).saturating_mul(128);
            let (hash_done, hash_work) = hash_walk.step(writer.slice(6..self.written), hash_budget);
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
        let compressor = self
            .compressor
            .get_or_insert_with(|| Compress::new(Compression::new(level as u32), true));
        let input_at = usize::try_from(compressor.total_in()).map_err(|_| BifError::SystemLimit)?;
        let output_at =
            usize::try_from(compressor.total_out()).map_err(|_| BifError::SystemLimit)?;
        if input_at > input.len() || output_at > output.len() {
            return Err(BifError::SystemLimit);
        }
        if output_at == output.len() {
            return Ok((self.compression_finished, 0));
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
        self.compression_finished = status == Status::StreamEnd;
        Ok((self.compression_finished, written))
    }

    /// Whether the compressed stream fits the size of its plain ETF binary.
    pub fn compression_is_useful(&self) -> bool {
        self.compression_finished
            && self.compressor.as_ref().is_some_and(|compressor| {
                compressor.total_out().saturating_add(6) <= self.encoded_size as u64
            })
    }

    /// Whether the zlib stream reached its final block.
    pub fn compression_finished(&self) -> bool {
        self.compression_finished
    }

    /// Number of compressed payload bytes emitted so far.
    pub fn compressed_payload_len(&self) -> Option<usize> {
        self.compressor
            .as_ref()
            .and_then(|compressor| usize::try_from(compressor.total_out()).ok())
    }

    /// Whether the destination has no remaining compressed payload capacity.
    pub fn compression_output_full(&self) -> bool {
        self.compressor.as_ref().is_some_and(|compressor| {
            compressor.total_out() >= self.encoded_size.saturating_sub(6) as u64
        })
    }

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
        let opts = self.opts;
        let splits = &mut self.splits;
        let work = &mut self.work;
        let iovec = self.iovec;
        let mut free_first = self.free_first;
        while consumed + 1 < budget
            || (free_first && matches!(work.last(), Some(Work::Term(_) | Work::OneCons { .. })))
        {
            let Some(item) = work.pop() else {
                break;
            };
            let term = match item {
                Work::PatchFun(at) => {
                    consumed += 1;
                    let size = u32::try_from(out.len() - at).map_err(|_| BifError::SystemLimit)?;
                    out.patch(at, &size.to_be_bytes());
                    continue;
                }
                Work::Term(term) => {
                    if !std::mem::take(&mut free_first) {
                        consumed += 1;
                    }
                    term
                }
                Work::OneCons { list, len_at, len } => {
                    if !std::mem::take(&mut free_first) {
                        consumed += 1;
                    }
                    // SAFETY: the source cons stays live while this BIF is suspended.
                    let (head, tail) = unsafe { list.cons_ref() }.ok_or(BifError::BADARG)?;
                    let count = len.checked_add(1).ok_or(BifError::SystemLimit)?;
                    if tail.classify() == TermKind::List {
                        work.push(Work::OneCons {
                            list: tail,
                            len_at,
                            len: count,
                        });
                    } else {
                        out.patch(len_at, &count.to_be_bytes());
                        work.push(Work::Term(tail));
                    }
                    head
                }
                Work::BinaryCopy {
                    term,
                    bits,
                    copied,
                    start,
                } => {
                    // Port of erts/emulator/beam/external.c:3820-3885 (ENC_BIN_COPY), OTP-29.1.1.
                    let len = bits.div_ceil(8);
                    let amount = len
                        .saturating_sub(copied)
                        .min(budget.saturating_sub(consumed).max(1));
                    let bit_count = (amount * 8).min(bits.saturating_sub(copied * 8));
                    out.write_bitstring(term, copied * 8, bit_count)?;
                    consumed += amount;
                    if copied + amount < len {
                        work.push(Work::BinaryCopy {
                            term,
                            bits,
                            copied: copied + amount,
                            start,
                        });
                    } else {
                        if bits % 8 != 0 {
                            out.mask_last(0xff << (8 - bits % 8));
                        }
                        if len > 64 {
                            splits.push((start, out.len()));
                        }
                    }
                    continue;
                }
                Work::MapGather {
                    mut entries,
                    mut pairs,
                } => {
                    consumed += 1;
                    if let Some(pair) = entries.next() {
                        pairs.push(pair);
                        work.push(Work::MapGather { entries, pairs });
                    } else if opts.deterministic {
                        work.push(Work::MapSort(MapSort::new(pairs)));
                    } else {
                        push_map_terms(work, pairs);
                    }
                    continue;
                }
                Work::MapEntries(mut entries) => {
                    if let Some((key, value)) = entries.next() {
                        work.push(Work::MapEntries(entries));
                        work.push(Work::Term(value));
                        work.push(Work::Term(key));
                    }
                    continue;
                }
                Work::MapSort(mut sorting) => {
                    let work_budget = budget.saturating_sub(consumed).max(1);
                    consumed += sorting.step(work_budget);
                    if sorting.is_done() {
                        push_map_terms(work, sorting.finish());
                    } else {
                        work.push(Work::MapSort(sorting));
                    }
                    continue;
                }
            };
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
                TermKind::Atom => atom_term(out, term, opts.minor)?,
                TermKind::Nil => out.push(106),
                TermKind::List => {
                    // Port of erts/emulator/beam/external.c:3703 (LIST_DEF), OTP-29.1.1.
                    if let Some(len) = external_string_len(term)? {
                        out.push(107);
                        out.extend_from_slice(&(len as u16).to_be_bytes());
                        let mut cursor = term;
                        for _ in 0..len {
                            // SAFETY: external_string_len already walked these cons cells.
                            let (head, tail) =
                                unsafe { cursor.cons_ref() }.ok_or(BifError::BADARG)?;
                            out.push(head.as_small().ok_or(BifError::BADARG)? as u8);
                            cursor = tail;
                        }
                        consumed += len;
                    } else {
                        // Port of erts/emulator/beam/external.c (LIST_DEF), OTP-29.1.1.
                        consumed += external_string_prefix(term).0 / 2;
                        out.push(108);
                        let len_at = out.len();
                        out.extend_from_slice(&0u32.to_be_bytes());
                        work.push(Work::OneCons {
                            list: term,
                            len_at,
                            len: 0,
                        });
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
                    for index in (0..arity).rev() {
                        work.push(Work::Term(crate::pure::tuple_element(term, index)?));
                    }
                }
                TermKind::Map => {
                    out.push(116);
                    let entries = MapEntries::new(term)?;
                    let len = entries.size;
                    out.extend_from_slice(
                        &u32::try_from(len)
                            .map_err(|_| BifError::SystemLimit)?
                            .to_be_bytes(),
                    );
                    if opts.deterministic {
                        work.push(Work::MapGather {
                            entries,
                            pairs: Vec::with_capacity(len),
                        });
                    } else {
                        work.push(Work::MapEntries(entries));
                    }
                }
                TermKind::Bitstring => {
                    // SAFETY: the binary owner remains live and no append runs during encoding.
                    let view = unsafe { term.binary_ref() }.ok_or(BifError::BADARG)?;
                    let bits = view.bit_len();
                    let len = bits.div_ceil(8);
                    let n = u32::try_from(len).map_err(|_| BifError::SystemLimit)?;
                    if bits.is_multiple_of(8) {
                        out.push(109);
                        out.extend_from_slice(&n.to_be_bytes());
                    } else {
                        out.push(77);
                        out.extend_from_slice(&n.to_be_bytes());
                        out.push((bits % 8) as u8);
                    }
                    let start = out.len();
                    if len != 0 {
                        // Port of erts/emulator/beam/external.c (BITSTRING_DEF), OTP-29.1.1.
                        let copy_payload = bits <= 64 * 8
                            || !iovec
                            || crate::pure::with_binary_bytes(term, |view| {
                                view.start_bit() % 8 != 0
                            })?;
                        let left = budget.saturating_sub(consumed);
                        if copy_payload && len > left.saturating_mul(8) {
                            work.push(Work::BinaryCopy {
                                term,
                                bits,
                                copied: 0,
                                start,
                            });
                        } else {
                            out.write_bitstring(term, 0, bits)?;
                            if bits % 8 != 0 {
                                out.mask_last(0xff << (8 - bits % 8));
                            }
                            if len > 64 {
                                splits.push((start, out.len()));
                            }
                        }
                    }
                }
                TermKind::Pid | TermKind::Port | TermKind::Ref => {
                    let identity = term.identity().ok_or(BifError::BADARG)?;
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
                        atom_term(out, Term::atom(entry.module), opts.minor)?;
                        atom_term(out, Term::atom(entry.function), opts.minor)?;
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
                        atom_term(out, Term::atom(entry.module), opts.minor)?;
                        write_small(out, i64::from(entry.old_index));
                        write_small(out, i64::from(entry.old_uniq));
                        work.push(Work::PatchFun(at));
                        let view = fun_of(term)?;
                        for i in (0..view.num_free()).rev() {
                            work.push(Work::Term(view.free(i).ok_or(BifError::BADARG)?));
                        }
                        work.push(Work::Term(entry.pid));
                    }
                },
                TermKind::Record => {
                    // Port of erts/emulator/beam/external.c:4010-4031, OTP-29.1.1.
                    let record = record_of(term)?;
                    out.push(67);
                    out.extend_from_slice(&(record.len() as u32).to_be_bytes());
                    out.push(u8::from(record.is_exported()));
                    atom_term(out, Term::atom(record.module()), opts.minor)?;
                    atom_term(out, Term::atom(record.name()), opts.minor)?;
                    for i in 0..record.len() {
                        let sorted = record.sorted_index(i).ok_or(BifError::BADARG)?;
                        atom_term(
                            out,
                            Term::atom(record.key(sorted).ok_or(BifError::BADARG)?),
                            opts.minor,
                        )?;
                    }
                    for i in (0..record.len()).rev() {
                        let sorted = record.sorted_index(i).ok_or(BifError::BADARG)?;
                        work.push(Work::Term(record.value(sorted).ok_or(BifError::BADARG)?));
                    }
                }
                _ => return Err(BifError::Unsupported("ETF representation")),
            }
        }
        let done = work.is_empty();
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
            return encode_bytes(self.out.into_vec(), self.opts).map(SmallVec::from_vec);
        }
        Ok(self.out)
    }

    fn patch_local_hash(&mut self) {
        if self.opts.local {
            let hash = local_term_hash(&self.out[6..]);
            self.out[2..6].copy_from_slice(&hash.to_be_bytes());
        }
    }

    /// Finish as `term_to_iovec/1,2`, preserving large-binary split boundaries.
    pub fn finish_iovec(mut self) -> Result<(Vec<Vec<u8>>, bool), BifError> {
        self.patch_local_hash();
        if self.opts.compressed.is_some_and(|level| level > 0) {
            return Ok((vec![encode_bytes(self.out.into_vec(), self.opts)?], true));
        }
        let Self { out, splits, .. } = self;
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
    walk.step(usize::MAX)?;
    walk.patch_local_hash();
    Ok((walk.out.into_vec(), walk.splits.into_vec()))
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

fn term_to_binary(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let opts = options(args.get(1).copied())?;
    let mut encoder = EncodeWalk::start(args[0], opts);
    encoder.step_size(usize::MAX)?;
    let size = encoder.encoded_size().ok_or(BifError::SystemLimit)?;
    if encoder.finishes_simple() {
        let binary = encoder.encode_simple_binary(&mut ctx.heap)?;
        ctx.charge_reductions(size);
        return Ok(binary);
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

fn external_size(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
    let mut opts = options(args.get(1).copied())?;
    opts.compressed = None;
    let mut encoder = EncodeWalk::start(args[0], opts);
    encoder.step_size(usize::MAX)?;
    let size = encoder.encoded_size().ok_or(BifError::SystemLimit)?;
    // Port of erts/emulator/beam/external.c (external_size_1), OTP-29.1.1: the size
    // is computed in one go without charging reductions.
    integer(ctx, size)
}

fn term_to_iovec(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
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

struct Reader {
    bytes: SmallVec<[u8; 64]>,
    at: usize,
}
impl Reader {
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
    fn atom(
        &mut self,
        safe: bool,
        ctx: &mut Option<&mut Ctx<'_>>,
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
    List,
    Map,
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
    if let FrameKind::Tuple { slots } = &mut frame.kind {
        if let Some(slots) = slots {
            slots.write_term(term).map_err(map_term_build_error)?;
        }
    } else {
        frame.values.push(term);
        frame.shapes.push(shape);
    }
    Ok(())
}

fn finish(frame: Frame, ctx: &mut Option<&mut Ctx<'_>>) -> Result<(Term, Shape), BifError> {
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
        FrameKind::List => {
            let mut it = values.into_iter().rev();
            let mut tail = it.next().ok_or(BifError::BADARG)?;
            if ctx.is_some() {
                for head in it {
                    tail = built(ctx, |b| b.cons(head, tail))?;
                }
            }
            Ok((tail, Shape::Other))
        }
        FrameKind::Map => {
            // Port of erts/emulator/beam/external.c:5428, OTP-29.1.1.
            let pairs: SmallVec<[(Term, Term); 4]> = values
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| (p[0], p[1]))
                .collect();
            if ctx.is_some() {
                let ctx = ctx.as_deref_mut().unwrap();
                let map = arinsal_maps::from_pairs(&pairs, &mut ctx.heap)
                    .map_err(|_| BifError::BADARG)?;
                if arinsal_maps::size(map).map_err(|_| BifError::BADARG)? != pairs.len() {
                    return Err(BifError::BADARG);
                }
                Ok((map, Shape::Other))
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

fn parse_step(
    r: &mut Reader,
    stack: &mut SmallVec<[Frame; 4]>,
    safe: bool,
    mut ctx: Option<&mut Ctx<'_>>,
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
                            FrameKind::List
                        } else {
                            FrameKind::Map
                        },
                        left: count,
                        values: SmallVec::with_capacity(count.min(1024)),
                        shapes: SmallVec::with_capacity(count.min(1024)),
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
                let identity = if tag == 103 || tag == 88 {
                    let id = r.u32()?;
                    let serial = r.u32()?;
                    let creation = if tag == 103 { r.u8()? as u32 } else { r.u32()? };
                    if tag == 103 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (id as u64, serial, creation, Vec::new())
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
                    (id, 0, creation, Vec::new())
                } else if tag == 101 {
                    let id = r.u32()?;
                    let creation = r.u8()? as u32;
                    if id >= (1 << 18) || creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    (0, 0, creation, vec![id])
                } else {
                    let creation = if tag == 90 { r.u32()? } else { r.u8()? as u32 };
                    if tag != 90 && creation > 3 {
                        return Err(BifError::BADARG);
                    }
                    let mut ids = Vec::with_capacity(count);
                    for i in 0..count {
                        let id = r.u32()?;
                        if i == 0 && tag != 90 && id >= (1 << 18) {
                            return Err(BifError::BADARG);
                        }
                        ids.push(id);
                    }
                    (0, 0, creation, ids)
                };
                let (id, serial, creation, ids) = identity;
                let t = if ctx.is_none() {
                    Term::NIL
                } else if tag == 103 || tag == 88 {
                    if node == arinsal_term::atoms::NONAME && creation == 0 {
                        Term::pid(id as u32, serial).ok_or(BifError::BADARG)?
                    } else {
                        built(&mut ctx, |b| {
                            b.external_pid(Node::new(node, creation), id as u32, serial)
                        })?
                    }
                } else if matches!(tag, 102 | 89 | 120) {
                    if node == arinsal_term::atoms::NONAME && creation == 0 {
                        Term::port(id).ok_or(BifError::BADARG)?
                    } else {
                        built(&mut ctx, |b| b.external_port(Node::new(node, creation), id))?
                    }
                } else if node == arinsal_term::atoms::NONAME && creation == 0 {
                    // Port of erts/emulator/beam/external.c (dec_term, NEWER_REFERENCE_EXT),
                    // OTP-29.1.1: numbers of a saved magic reference give that reference.
                    let mut local = [0; 3];
                    for (slot, value) in local.iter_mut().zip(ids) {
                        *slot = value;
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
                        b.external_ref(Node::new(node, creation), &ids)
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
    let mut reader = Reader {
        bytes: SmallVec::from_slice(bytes),
        at: 0,
    };
    let mut stack = SmallVec::new();
    match parse_step(&mut reader, &mut stack, safe, ctx, usize::MAX, true)? {
        Some(value) => Ok(value),
        None => Err(BifError::BADARG),
    }
}

/// Incremental ETF validator retained by `binary_to_term_trap/1`.
pub struct DecodeWalk {
    reader: Reader,
    stack: SmallVec<[Frame; 4]>,
    safe: bool,
    used: bool,
    compressed: bool,
    used_prefix: usize,
    input_size: usize,
    compressed_input: SmallVec<[u8; 64]>,
    input_offset: usize,
    expected_plain: usize,
    decompressor: Option<Decompress>,
    inflate_done: bool,
    checked_root: Option<usize>,
    decoded_root: Option<Term>,
}

impl DecodeWalk {
    /// Start decoding an ETF binary and retain its compressed payload if needed.
    pub fn new(args: &[Term]) -> Result<Self, BifError> {
        let opts = decode_options(args.get(1).copied())?;
        // SAFETY: the input binary owner is live and stable during the BIF call.
        let view = unsafe { args[0].binary_ref() }.ok_or(BifError::BADARG)?;
        if !view.bit_len().is_multiple_of(8) {
            return Err(BifError::BADARG);
        }
        let bytes = if view.start_bit().is_multiple_of(8) {
            let start = view.start_bit() / 8;
            let mut bytes = SmallVec::new();
            bytes.extend_from_slice(&view.bytes()[start..start + view.bit_len() / 8]);
            bytes
        } else {
            bit_bytes(args[0])?.0
        };
        if bytes.first() != Some(&131) {
            return Err(BifError::BADARG);
        }
        let (plain, used_prefix, compressed, compressed_input, expected_plain, decompressor) =
            if bytes.get(1) == Some(&80) {
                if bytes.len() < 6 {
                    return Err(BifError::BADARG);
                }
                let size = u32::from_be_bytes(bytes[2..6].try_into().unwrap()) as usize;
                (
                    SmallVec::new(),
                    6,
                    true,
                    SmallVec::from_slice(&bytes[6..]),
                    size,
                    Some(Decompress::new(true)),
                )
            } else {
                (
                    SmallVec::from_slice(&bytes[1..]),
                    1,
                    false,
                    SmallVec::new(),
                    0,
                    None,
                )
            };
        Ok(Self {
            reader: Reader {
                bytes: plain,
                at: 0,
            },
            stack: SmallVec::new(),
            safe: opts.safe,
            used: opts.used,
            compressed,
            used_prefix,
            input_size: bytes.len(),
            compressed_input,
            input_offset: 0,
            expected_plain,
            decompressor,
            inflate_done: !compressed,
            checked_root: None,
            decoded_root: None,
        })
    }

    fn inflate_more(&mut self, output_budget: usize) -> Result<usize, BifError> {
        if self.inflate_done {
            return Ok(0);
        }
        let remaining = self.expected_plain.saturating_sub(self.reader.bytes.len());
        let capacity = output_budget.max(1).min(remaining.saturating_add(1));
        let mut output = SmallVec::<[u8; 128]>::new();
        output.resize(capacity, 0);
        let input = &self.compressed_input[self.input_offset..];
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
        if self.reader.bytes.len().saturating_add(produced) > self.expected_plain {
            return Err(BifError::BADARG);
        }
        self.reader.bytes.extend_from_slice(&output[..produced]);
        if status == Status::StreamEnd {
            self.inflate_done = true;
            self.used_prefix = 6 + self.input_offset;
            if self.reader.bytes.len() != self.expected_plain {
                return Err(BifError::BADARG);
            }
        } else if consumed == 0 && produced == 0 {
            return Err(BifError::BADARG);
        }
        Ok(produced)
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
                if checked != self.expected_plain || self.reader.bytes.len() != checked {
                    return Err((BifError::BADARG, consumed));
                }
                return Ok((Some(checked), consumed));
            }
            return Ok((None, consumed));
        }
        while consumed < byte_budget.max(1) {
            let before = self.reader.at;
            // One dec_term loop when the plain text is complete. Compressed
            // chunks stay at one tag so inflate can refill the buffer.
            let tags = if self.compressed && !self.inflate_done {
                1
            } else {
                byte_budget.saturating_sub(consumed).max(1)
            };
            match parse_step(
                &mut self.reader,
                &mut self.stack,
                self.safe,
                None,
                tags,
                !self.compressed || self.inflate_done,
            ) {
                Ok(Some((_, checked))) => {
                    consumed += self.reader.at - before;
                    if self.compressed && !self.inflate_done {
                        self.checked_root = Some(checked);
                        let produced = self
                            .inflate_more(byte_budget.saturating_sub(consumed))
                            .map_err(|error| (error, consumed))?;
                        consumed += produced.max(1);
                        continue;
                    }
                    if self.compressed && checked != self.reader.bytes.len() {
                        return Err((BifError::BADARG, consumed));
                    }
                    return Ok((Some(checked), consumed));
                }
                Ok(None) => consumed += self.reader.at - before,
                Err(BifError::Unsupported("incomplete ETF input")) => {
                    self.reader.at = before;
                    if !self.compressed || self.inflate_done {
                        return Err((BifError::BADARG, consumed));
                    }
                    let produced = self
                        .inflate_more(byte_budget.saturating_sub(consumed))
                        .map_err(|error| (error, consumed))?;
                    consumed += produced.max(1);
                }
                Err(error) => return Err((error, consumed + self.reader.at - before)),
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
        if let Some(checked) = self.checked_root {
            while !self.inflate_done && consumed < byte_budget.max(1) {
                let produced = self
                    .inflate_more(byte_budget.saturating_sub(consumed))
                    .map_err(|error| (error, consumed))?;
                consumed += produced.max(1);
            }
            if self.inflate_done {
                if checked != self.expected_plain || self.reader.bytes.len() != checked {
                    return Err((BifError::BADARG, consumed));
                }
                let term = self
                    .decoded_root
                    .take()
                    .ok_or((BifError::BADARG, consumed))?;
                return self
                    .wrap_used(ctx, term, checked)
                    .map(|value| (Some(value), consumed))
                    .map_err(|error| (error, consumed));
            }
            return Ok((None, consumed));
        }
        while consumed < byte_budget.max(1) {
            let before = self.reader.at;
            let tags = if self.compressed && !self.inflate_done {
                1
            } else {
                byte_budget.saturating_sub(consumed).max(1)
            };
            match parse_step(
                &mut self.reader,
                &mut self.stack,
                self.safe,
                Some(ctx),
                tags,
                !self.compressed || self.inflate_done,
            ) {
                Ok(Some((term, checked))) => {
                    consumed += self.reader.at - before;
                    if self.compressed && !self.inflate_done {
                        self.checked_root = Some(checked);
                        self.decoded_root = Some(term);
                        let produced = self
                            .inflate_more(byte_budget.saturating_sub(consumed))
                            .map_err(|error| (error, consumed))?;
                        consumed += produced.max(1);
                        continue;
                    }
                    if self.compressed && checked != self.reader.bytes.len() {
                        return Err((BifError::BADARG, consumed));
                    }
                    let value = self
                        .wrap_used(ctx, term, checked)
                        .map_err(|error| (error, consumed))?;
                    return Ok((Some(value), consumed));
                }
                Ok(None) => consumed += self.reader.at - before,
                Err(BifError::Unsupported("incomplete ETF input")) => {
                    self.reader.at = before;
                    if !self.compressed || self.inflate_done {
                        return Err((BifError::BADARG, consumed));
                    }
                    let produced = self
                        .inflate_more(byte_budget.saturating_sub(consumed))
                        .map_err(|error| (error, consumed))?;
                    consumed += produced.max(1);
                }
                Err(error) => return Err((error, consumed + self.reader.at - before)),
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
            parse(&self.reader.bytes[..checked], self.safe, Some(ctx)).map_err(decode_error)?;
        self.wrap_used(ctx, term, checked)
    }

    /// Return the original ETF byte length for reduction accounting.
    pub fn input_size(&self) -> usize {
        self.input_size
    }
}

fn binary_to_term(ctx: &mut Ctx<'_>, args: &[Term]) -> Result<Term, BifError> {
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

#[cfg(test)]
mod map_sort_tests {
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

crate::bif_bodies!(term_to_binary, term_to_iovec, external_size, binary_to_term,);
