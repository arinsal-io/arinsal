//! OTP 29.1.1 flatmaps and 64-bit HAMT maps.
//!
//! Flatmap atoms compare by atom-table index (`erl_utils.h:267`), while other
//! keys compare in exact term order. For example, if `zzzz_new` is interned
//! before `aaaa_new`, `maps:to_list/1` returns `zzzz_new` first. The generated
//! OTP `atom.names` table gives Arinsal the same predefined atom indices;
//! later atom indices depend on first intern order. Normal OTP 29.1.1 uses
//! unsalted `erts_internal_hash` for HAMT keys. Trie iteration visits slots
//! from 0 to 15 at each depth, independently of insertion order.

use arinsal_term::{
    ExportEntry, FunEntry, HeapAlloc, Node, Term, TermBuilder, TermError, TermKind, WritableBinary,
    cmp, exact_eq, global_atoms, internal_hash,
};
use std::cmp::Ordering;
use std::sync::Arc;

mod merge;
pub use merge::{
    HashmapMergeContext, MAP_MERGE_LOOP_FACTOR, MergeStart, from_keys, from_list, hashmap_merge,
    merge, merge_start,
};

const MAP: u64 = 0x2c;
const LIMIT: usize = 32;
static EMPTY_TUPLE: u64 = 0;

/// Map operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// `{badmap, Term}`.
    Badmap(Term),
    /// `{badkey, Key}`.
    Badkey(Term),
    /// Caller must collect garbage and retry with this many words.
    HeapFull { need_words: usize },
    /// Invalid iterator term or path.
    Badarg(Term),
    /// Unsupported key term. Retained for API compatibility; map operations no longer produce it.
    #[deprecated(note = "map keys use arinsal-term hashing and comparison")]
    UnsupportedKey(Term),
}

/// Map operation result.
pub type MapResult<T> = Result<T, MapError>;

fn bits(t: Term) -> u64 {
    // SAFETY: pointer-bearing terms remain owned by their live heap.
    unsafe { t.raw_bits() }
}
fn term(word: u64) -> Term {
    // SAFETY: Term is repr(transparent) over u64; map words hold tagged terms.
    unsafe { std::mem::transmute::<u64, Term>(word) }
}
fn boxed(ptr: *mut u64) -> Term {
    term(ptr as u64 | 2)
}
fn cons(ptr: *mut u64) -> Term {
    term(ptr as u64 | 1)
}
fn check(map: Term) -> MapResult<()> {
    if map.classify() == TermKind::Map {
        Ok(())
    } else {
        Err(MapError::Badmap(map))
    }
}

// Port of erts/emulator/beam/erl_utils.h:267 (erts_cmp_flatmap_keys), OTP-29.1.1.
fn key_cmp(a: Term, b: Term) -> Ordering {
    exact_cmp(a, b, true)
}

/// Flatmap key order (atoms by atom index), as erts `CMP_TERM` for flatmap keys.
pub fn flatmap_key_cmp(a: Term, b: Term) -> Ordering {
    key_cmp(a, b)
}
fn exact_cmp(a: Term, b: Term, flat_atom: bool) -> Ordering {
    if let (Some(a), Some(b)) = (a.as_atom(), b.as_atom())
        && flat_atom
    {
        return a.0.cmp(&b.0);
    }
    if a.classify() == TermKind::Number && b.classify() == TermKind::Number {
        let afloat = a.header().is_some_and(|h| h & 63 == 0x18);
        let bfloat = b.header().is_some_and(|h| h & 63 == 0x18);
        return match (afloat, bfloat) {
            (false, true) => Ordering::Less,
            (true, false) => Ordering::Greater,
            (true, true) => {
                // SAFETY: float headers identify live two-word float objects.
                unsafe {
                    a.float_ref()
                        .unwrap()
                        .get()
                        .total_cmp(&b.float_ref().unwrap().get())
                }
            }
            (false, false) => cmp(a, b),
        };
    }
    match (a.classify(), b.classify()) {
        (TermKind::Tuple, TermKind::Tuple) => {
            // SAFETY: both tuple terms remain live throughout key comparison.
            let (a, b) = unsafe { (a.tuple_ref().unwrap(), b.tuple_ref().unwrap()) };
            let order = a.len().cmp(&b.len());
            if order != Ordering::Equal {
                return order;
            }
            for i in 0..a.len() {
                let order = exact_cmp(a.get(i).unwrap(), b.get(i).unwrap(), false);
                if order != Ordering::Equal {
                    return order;
                }
            }
            Ordering::Equal
        }
        (TermKind::List, TermKind::List) => {
            // SAFETY: both list terms remain live throughout key comparison.
            let ((ah, at), (bh, bt)) = unsafe { (a.cons_ref().unwrap(), b.cons_ref().unwrap()) };
            exact_cmp(ah, bh, false).then_with(|| exact_cmp(at, bt, false))
        }
        (TermKind::Map, TermKind::Map) => cmp(a, b),
        _ => cmp(a, b),
    }
}
fn unique(pairs: &[(Term, Term)]) -> Vec<(Term, Term)> {
    let mut sorted: Vec<_> = pairs.iter().copied().enumerate().collect();
    sorted.sort_by(|a, b| key_cmp(a.1.0, b.1.0).then(a.0.cmp(&b.0)));
    let mut out: Vec<(Term, Term)> = Vec::with_capacity(sorted.len());
    for (_, pair) in sorted {
        if out.last().is_some_and(|last| exact_eq(last.0, pair.0)) {
            *out.last_mut().unwrap() = pair;
        } else {
            out.push(pair);
        }
    }
    out
}
fn flat<H: HeapAlloc + ?Sized>(pairs: &[(Term, Term)], heap: &mut H) -> MapResult<Term> {
    let ks: Vec<Term> = pairs.iter().map(|p| p.0).collect();
    let vs: Vec<Term> = pairs.iter().map(|p| p.1).collect();
    merge::flatmap_from_sorted(&ks, &vs, heap).map_err(|_| MapError::HeapFull {
        need_words: if pairs.is_empty() {
            3
        } else {
            4 + 2 * pairs.len()
        },
    })
}
/// The empty flatmap, sharing the static empty key tuple.
fn empty_flatmap<H: HeapAlloc + ?Sized>(heap: &mut H) -> Result<Term, TermError> {
    // Port of erts/emulator/beam/erl_map.c:379-383 (ERTS_GLOBAL_LIT_EMPTY_TUPLE keys), OTP-29.1.1.
    let (slice, ptr) = merge::produce(heap, 3)?;
    slice[0].write(MAP);
    slice[1].write(0);
    slice[2].write(bits(boxed((&EMPTY_TUPLE as *const u64).cast_mut())));
    Ok(boxed(ptr))
}

struct SizingHeap<'a, H: HeapAlloc + ?Sized> {
    inner: &'a mut H,
    requested_words: usize,
}
impl<H: HeapAlloc + ?Sized> HeapAlloc for SizingHeap<'_, H> {
    fn alloc(&mut self, words: usize) -> Option<*mut u64> {
        self.requested_words = self.requested_words.saturating_add(words);
        self.inner.alloc(words)
    }
    fn retain_binary(&mut self, binary: Arc<arinsal_term::RefcBinary>) {
        self.inner.retain_binary(binary);
    }
    fn retain_writable_binary(&mut self, binary: Arc<WritableBinary>) -> Result<(), TermError> {
        self.inner.retain_writable_binary(binary)
    }
    fn supports_writable_binary(&self) -> bool {
        self.inner.supports_writable_binary()
    }
    fn retain_node(&mut self, node: Arc<Node>) {
        self.inner.retain_node(node);
    }
    fn retain_fun(&mut self, entry: Arc<FunEntry>) {
        self.inner.retain_fun(entry);
    }
    fn retain_export(&mut self, entry: Arc<ExportEntry>) {
        self.inner.retain_export(entry);
    }
}

fn build_hamt<H: HeapAlloc + ?Sized>(pairs: &[(Term, Term)], heap: &mut H) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:712-759 (erts_hashmap_from_ks_and_vs_extra), OTP-29.1.1.
    merge::sized(heap, |heap| {
        arinsal_term::build_hamt_from_unique(pairs, heap)
    })
}
fn flat_replace<H: HeapAlloc + ?Sized>(
    map: Term,
    at: usize,
    value: Term,
    heap: &mut H,
) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:2070-2096, OTP-29.1.1.
    // SAFETY: check() established a live flatmap and the source heap remains live.
    let view = unsafe { map.flatmap_ref().unwrap() };
    let n = view.len();
    let need_words = 3 + n;
    let p = heap
        .alloc(need_words)
        .ok_or(MapError::HeapFull { need_words })?;
    // SAFETY: the source key tuple is reused; allocation holds n values.
    unsafe {
        std::ptr::copy_nonoverlapping(map.raw_ptr(), p, need_words);
        *p.add(3 + at) = bits(value);
    }
    Ok(boxed(p))
}

// Port of erts/emulator/beam/erl_map.h:178-205 (HAMT headers), OTP-29.1.1.
fn header(kind: u64, bitmap: u16) -> u64 {
    MAP | kind << 6 | u64::from(kind == 2 || kind == 3) << 8 | (bitmap as u64) << 16
}
fn slot(hash: u64, level: usize) -> usize {
    // Port of erts/emulator/beam/erl_map.c:2424-2474, OTP-29.1.1.
    ((hash >> (4 * level)) & 15) as usize
}

const MAX_HAMT_DEPTH: usize = 18;
const FRAME_INSERT: u32 = 1 << 4;

// Port of erts/emulator/beam/erl_map.c:2477-2794 (erts_hashmap_insert and
// insert_down/insert_up), OTP-29.1.1. The fixed path is the Rust equivalent of
// OTP's ESTACK; sizing and path discovery happen together.
fn hashmap_insert<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    value: Term,
    is_update: bool,
    heap: &mut H,
) -> MapResult<Term> {
    let mut path = [(map, 0_u32, 0_u32); MAX_HAMT_DEPTH];
    let mut depth = 0;
    let mut node = map;
    let mut level = 0;
    let hash = internal_hash(key);
    let mut old_leaf = None;
    let mut leaf_split_level = 0;
    let mut new_key = true;
    let mut need_words = 2;

    // SAFETY: map and all terms reachable from it belong to live heaps; the
    // single allocation below reserves every word written during path rebuild.
    unsafe {
        loop {
            if bits(node) & 3 == 1 {
                let ptr = node.raw_ptr();
                let old_key = term(*ptr);
                if exact_eq(old_key, key) {
                    new_key = false;
                    if term(*ptr.add(1)) == value {
                        return Ok(map);
                    }
                } else {
                    if is_update {
                        return Err(MapError::Badkey(key));
                    }
                    old_leaf = Some((node, old_key));
                    leaf_split_level = level;
                }
                break;
            }

            let ptr = node.raw_ptr();
            let header_word = *ptr;
            if header_word & 63 == 0 {
                let arity = (header_word >> 6) as usize;
                let mut index = 0;
                while index < arity {
                    let leaf = term(*ptr.add(1 + index));
                    let candidate = term(*leaf.raw_ptr());
                    match exact_cmp(key, candidate, false) {
                        Ordering::Equal => break,
                        Ordering::Less => break,
                        Ordering::Greater => index += 1,
                    }
                }
                let found =
                    index < arity && exact_eq(term(*term(*ptr.add(1 + index)).raw_ptr()), key);
                if !found && is_update {
                    return Err(MapError::Badkey(key));
                }
                if found {
                    let leaf = term(*ptr.add(1 + index));
                    if term(*leaf.raw_ptr().add(1)) == value {
                        return Ok(map);
                    }
                    new_key = false;
                }
                need_words += 1 + arity + usize::from(!found);
                path[depth] = (node, index as u32, if found { 0 } else { FRAME_INSERT });
                depth += 1;
                break;
            }

            let kind = ((header_word >> 6) & 3) as usize;
            let index = slot(hash, level);
            if kind == 2 {
                need_words += 18;
                path[depth] = (node, index as u32, index as u32);
                depth += 1;
                node = term(*ptr.add(2 + index));
                level += 1;
                continue;
            }

            let bitmap = ((header_word >> 16) & 0xffff) as u16;
            let bit = 1_u16 << index;
            let child_index = (bitmap & (bit - 1)).count_ones() as usize;
            let occupied = bitmap & bit != 0;
            if !occupied && is_update {
                return Err(MapError::Badkey(key));
            }
            need_words +=
                1 + usize::from(kind == 3) + bitmap.count_ones() as usize + usize::from(!occupied);
            path[depth] = (
                node,
                child_index as u32,
                index as u32 | if occupied { 0 } else { FRAME_INSERT },
            );
            depth += 1;
            if !occupied {
                break;
            }
            let offset = if kind == 3 { 2 } else { 1 };
            node = term(*ptr.add(offset + child_index));
            level += 1;
        }

        let old_split = old_leaf.map(|(leaf, old_key)| {
            let old_hash = internal_hash(old_key);
            let mut divergence = leaf_split_level;
            while divergence < 16 && slot(hash, divergence) == slot(old_hash, divergence) {
                divergence += 1;
            }
            (leaf, old_key, old_hash, divergence)
        });
        if let Some((_, _, _, divergence)) = old_split {
            need_words += if divergence == 16 {
                3
            } else {
                3 + 2 * (divergence - leaf_split_level)
            };
        }
        let mut cursor = heap
            .alloc(need_words)
            .ok_or(MapError::HeapFull { need_words })?;
        let inserted = cursor;
        *cursor = bits(key);
        *cursor.add(1) = bits(value);
        cursor = cursor.add(2);
        let mut replacement = cons(inserted);

        if let Some((old, old_key, old_hash, divergence)) = old_split {
            if divergence == 16 {
                *cursor = 2 << 6;
                let old_first = exact_cmp(key, old_key, false).is_gt();
                *cursor.add(1) = if old_first {
                    bits(old)
                } else {
                    bits(replacement)
                };
                *cursor.add(2) = if old_first {
                    bits(replacement)
                } else {
                    bits(old)
                };
                replacement = boxed(cursor);
                cursor = cursor.add(3);
            } else {
                let new_slot = slot(hash, divergence);
                let old_slot = slot(old_hash, divergence);
                *cursor = header(1, (1 << new_slot) | (1 << old_slot));
                *cursor.add(1) = if new_slot < old_slot {
                    bits(replacement)
                } else {
                    bits(old)
                };
                *cursor.add(2) = if new_slot < old_slot {
                    bits(old)
                } else {
                    bits(replacement)
                };
                replacement = boxed(cursor);
                cursor = cursor.add(3);
                for shared_level in (leaf_split_level..divergence).rev() {
                    *cursor = header(1, 1 << slot(hash, shared_level));
                    *cursor.add(1) = bits(replacement);
                    replacement = boxed(cursor);
                    cursor = cursor.add(2);
                }
            }
        }

        for &(frame, compact_index, meta) in path[..depth].iter().rev() {
            let source = frame.raw_ptr();
            let h = *source;
            let added = meta & FRAME_INSERT != 0;
            if h & 63 == 0 {
                let count = (h >> 6) as usize;
                let index = compact_index as usize;
                let out_count = count + usize::from(added);
                *cursor = (out_count as u64) << 6;
                std::ptr::copy_nonoverlapping(source.add(1), cursor.add(1), count);
                if added {
                    std::ptr::copy(cursor.add(1 + index), cursor.add(2 + index), count - index);
                }
                *cursor.add(1 + index) = bits(replacement);
                replacement = boxed(cursor);
                cursor = cursor.add(1 + out_count);
                continue;
            }

            let kind = ((h >> 6) & 3) as usize;
            let slot = (meta & 15) as usize;
            if kind == 2 {
                std::ptr::copy_nonoverlapping(source, cursor, 18);
                *cursor.add(2 + slot) = bits(replacement);
                if new_key {
                    *cursor.add(1) += 1;
                }
                replacement = boxed(cursor);
                cursor = cursor.add(18);
                continue;
            }

            let bitmap = ((h >> 16) & 0xffff) as u16;
            let count = bitmap.count_ones() as usize;
            let index = compact_index as usize;
            let out_bitmap = if added { bitmap | (1 << slot) } else { bitmap };
            let root = kind == 3;
            let out_kind = if root {
                if out_bitmap == u16::MAX { 2 } else { 3 }
            } else {
                1
            };
            let offset = 1 + usize::from(root);
            let out_count = count + usize::from(added);
            *cursor = header(out_kind, out_bitmap);
            if root {
                *cursor.add(1) = *source.add(1) + u64::from(new_key);
            }
            std::ptr::copy_nonoverlapping(source.add(offset), cursor.add(offset), count);
            if added {
                std::ptr::copy(
                    cursor.add(offset + index),
                    cursor.add(offset + index + 1),
                    count - index,
                );
            }
            *cursor.add(offset + index) = bits(replacement);
            replacement = boxed(cursor);
            cursor = cursor.add(offset + out_count);
        }
        Ok(replacement)
    }
}

// Port of erts/emulator/beam/erl_map.c:2881-3184 (hashmap_delete), OTP-29.1.1.
// Shape values model THE_NON_VALUE, a list leaf, and a boxed subtree.
fn hashmap_delete<H: HeapAlloc + ?Sized>(map: Term, key: Term, heap: &mut H) -> MapResult<Term> {
    const NONE: u8 = 0;
    const LEAF: u8 = 1;
    const BOXED: u8 = 2;
    let mut path = [(map, 0_u32, 0_u32); MAX_HAMT_DEPTH];
    let mut depth = 0;
    let mut node = map;
    let mut level = 0;
    let hash = internal_hash(key);

    // SAFETY: the source map and every child remain live during traversal; the
    // exact output size is computed from this bounded path before allocation.
    unsafe {
        loop {
            if bits(node) & 3 == 1 {
                let leaf = node.raw_ptr();
                if !exact_eq(term(*leaf), key) {
                    return Ok(map);
                }
                break;
            }

            let source = node.raw_ptr();
            let h = *source;
            if h & 63 == 0 {
                let arity = (h >> 6) as usize;
                let mut index = 0;
                while index < arity && !exact_eq(term(*term(*source.add(1 + index)).raw_ptr()), key)
                {
                    index += 1;
                }
                if index == arity {
                    return Ok(map);
                }
                path[depth] = (node, index as u32, 0);
                depth += 1;
                break;
            }

            let kind = ((h >> 6) & 3) as usize;
            let slot = slot(hash, level);
            if kind == 2 {
                path[depth] = (node, slot as u32, slot as u32);
                depth += 1;
                node = term(*source.add(2 + slot));
                level += 1;
                continue;
            }
            let bitmap = ((h >> 16) & 0xffff) as u16;
            let bit = 1_u16 << slot;
            if bitmap & bit == 0 {
                return Ok(map);
            }
            let index = (bitmap & (bit - 1)).count_ones() as usize;
            path[depth] = (node, index as u32, slot as u32);
            depth += 1;
            let offset = if kind == 3 { 2 } else { 1 };
            node = term(*source.add(offset + index));
            level += 1;
        }

        let mut shape = NONE;
        let mut need_words = 0;
        for &(frame, compact_index, _meta) in path[..depth].iter().rev() {
            let source = frame.raw_ptr();
            let h = *source;
            if h & 63 == 0 {
                let arity = (h >> 6) as usize;
                if arity == 2 {
                    let other = 1 - compact_index as usize;
                    let leaf = term(*source.add(1 + other));
                    shape = if bits(leaf) & 3 == 1 { LEAF } else { BOXED };
                } else {
                    need_words += arity;
                    shape = BOXED;
                }
                continue;
            }

            let kind = ((h >> 6) & 3) as usize;
            if kind == 2 {
                need_words += if shape == NONE { 17 } else { 18 };
                shape = BOXED;
                continue;
            }

            let bitmap = ((h >> 16) & 0xffff) as u16;
            let count = bitmap.count_ones() as usize;
            if kind == 3 {
                need_words += if shape == NONE { 1 + count } else { 2 + count };
                shape = BOXED;
                continue;
            }

            if shape == NONE {
                if count == 1 {
                    continue;
                }
                if count == 2 {
                    let sibling = term(*source.add(1 + (1 - compact_index as usize)));
                    if bits(sibling) & 3 == 1 {
                        shape = LEAF;
                    } else {
                        need_words += 2;
                        shape = BOXED;
                    }
                    continue;
                }
                need_words += count;
                shape = BOXED;
            } else if shape == LEAF && count == 1 {
                continue;
            } else {
                need_words += 1 + count;
                shape = BOXED;
            }
        }

        if need_words == 0 {
            return Ok(map);
        }
        let mut cursor = heap
            .alloc(need_words)
            .ok_or(MapError::HeapFull { need_words })?;
        let start = cursor;
        let mut replacement = None;

        for &(frame, compact_index, meta) in path[..depth].iter().rev() {
            let source = frame.raw_ptr();
            let h = *source;
            if h & 63 == 0 {
                let arity = (h >> 6) as usize;
                let index = compact_index as usize;
                if arity == 2 {
                    replacement = Some(term(*source.add(1 + (1 - index))));
                    continue;
                }
                *cursor = ((arity - 1) as u64) << 6;
                std::ptr::copy_nonoverlapping(source.add(1), cursor.add(1), index);
                std::ptr::copy_nonoverlapping(
                    source.add(2 + index),
                    cursor.add(1 + index),
                    arity - index - 1,
                );
                replacement = Some(boxed(cursor));
                cursor = cursor.add(arity);
                continue;
            }

            let kind = ((h >> 6) & 3) as usize;
            if kind == 2 {
                let removed_slot = (meta & 15) as usize;
                if replacement.is_none() {
                    let bitmap = u16::MAX ^ (1 << removed_slot);
                    *cursor = header(3, bitmap);
                    *cursor.add(1) = *source.add(1) - 1;
                    let mut out = 0;
                    for i in 0..16 {
                        if i != removed_slot {
                            *cursor.add(2 + out) = *source.add(2 + i);
                            out += 1;
                        }
                    }
                    replacement = Some(boxed(cursor));
                    cursor = cursor.add(17);
                } else {
                    std::ptr::copy_nonoverlapping(source, cursor, 18);
                    *cursor.add(1) -= 1;
                    *cursor.add(2 + removed_slot) = bits(replacement.unwrap());
                    replacement = Some(boxed(cursor));
                    cursor = cursor.add(18);
                }
                continue;
            }

            let bitmap = ((h >> 16) & 0xffff) as u16;
            let count = bitmap.count_ones() as usize;
            let index = compact_index as usize;
            let slot = (meta & 15) as usize;
            if kind == 3 {
                let output = cursor;
                let removed = replacement.is_none();
                let out_bitmap = if removed {
                    bitmap & !(1 << slot)
                } else {
                    bitmap
                };
                let out_count = count - usize::from(removed);
                *output = header(3, out_bitmap);
                *output.add(1) = *source.add(1) - 1;
                std::ptr::copy_nonoverlapping(source.add(2), output.add(2), index);
                if let Some(child) = replacement {
                    *output.add(2 + index) = bits(child);
                    std::ptr::copy_nonoverlapping(
                        source.add(3 + index),
                        output.add(3 + index),
                        count - index - 1,
                    );
                } else {
                    std::ptr::copy_nonoverlapping(
                        source.add(3 + index),
                        output.add(2 + index),
                        count - index - 1,
                    );
                }
                replacement = Some(boxed(output));
                cursor = cursor.add(2 + out_count);
                continue;
            }

            if replacement.is_none() {
                if count == 1 {
                    continue;
                }
                if count == 2 {
                    let other_index = 1 - index;
                    let sibling = term(*source.add(1 + other_index));
                    if bits(sibling) & 3 == 1 {
                        replacement = Some(sibling);
                    } else {
                        let remaining_slot = (bitmap & !(1 << slot)).trailing_zeros() as usize;
                        *cursor = header(1, 1 << remaining_slot);
                        *cursor.add(1) = bits(sibling);
                        replacement = Some(boxed(cursor));
                        cursor = cursor.add(2);
                    }
                    continue;
                }
                let out_bitmap = bitmap & !(1 << slot);
                *cursor = header(1, out_bitmap);
                std::ptr::copy_nonoverlapping(source.add(1), cursor.add(1), index);
                std::ptr::copy_nonoverlapping(
                    source.add(2 + index),
                    cursor.add(1 + index),
                    count - index - 1,
                );
                replacement = Some(boxed(cursor));
                cursor = cursor.add(count);
            } else {
                let child = replacement.unwrap();
                if bits(child) & 3 == 1 && count == 1 {
                    replacement = Some(child);
                    continue;
                }
                *cursor = h;
                std::ptr::copy_nonoverlapping(source.add(1), cursor.add(1), index);
                *cursor.add(1 + index) = bits(child);
                std::ptr::copy_nonoverlapping(
                    source.add(2 + index),
                    cursor.add(2 + index),
                    count - index - 1,
                );
                replacement = Some(boxed(cursor));
                cursor = cursor.add(1 + count);
            }
        }
        debug_assert_eq!(cursor.offset_from(start) as usize, need_words);
        Ok(replacement.unwrap_or(map))
    }
}

#[derive(Clone)]
enum Tree {
    Old(Term),
}
// Port of erts/emulator/beam/erl_map.c:2424 (bitmap child addressing), OTP-29.1.1.
fn children(node: Term) -> Vec<(usize, Tree)> {
    // SAFETY: a live HAMT node holds bitmap-indexed children.
    unsafe {
        let p = node.raw_ptr();
        let h = *p;
        let bitmap = ((h >> 16) & 0xffff) as u16;
        let offset = if (h >> 6) & 3 >= 2 { 2 } else { 1 };
        let mut result = Vec::with_capacity(bitmap.count_ones() as usize);
        let mut index = 0;
        for i in 0..16 {
            if bitmap & (1 << i) != 0 {
                result.push((i, Tree::Old(term(*p.add(offset + index)))));
                index += 1;
            }
        }
        result
    }
}
fn collision_children(node: Term) -> Vec<Tree> {
    // SAFETY: a live collision tuple holds arity entries.
    unsafe {
        let p = node.raw_ptr();
        (0..(*p >> 6) as usize)
            .map(|i| Tree::Old(term(*p.add(1 + i))))
            .collect()
    }
}
fn collect(node: Term, out: &mut Vec<(Term, Term)>) {
    // Port of erts/emulator/beam/erl_map.c:1930-1992, OTP-29.1.1.
    if bits(node) & 3 == 1 {
        out.push(merge::leaf(node));
        return;
    }
    let words = match merge::node_view(node) {
        merge::NodeView::Bitmap(children) => children,
        merge::NodeView::Collision(leaves) => leaves,
    };
    for &child in words {
        collect(term(child), out);
    }
}

/// `map_size(Map)`.
pub fn size(map: Term) -> MapResult<usize> {
    // Port of erts/emulator/beam/erl_map.c:1380-1399, OTP-29.1.1.
    check(map)?;
    // SAFETY: both flatmap and HAMT head have untagged size in word one.
    Ok(unsafe { *map.raw_ptr().add(1) as usize })
}
/// Lookup; `Ok(None)` when the key is absent.
pub fn get(map: Term, key: Term) -> MapResult<Option<Term>> {
    // Port of erts/emulator/beam/erl_map.c:2424-2474, OTP-29.1.1.
    check(map)?;
    if !map.is_hashmap() {
        // SAFETY: the source heap remains live during this operation.
        return Ok(unsafe { map.flatmap_ref().unwrap() }.get(key));
    }
    let mut node = map;
    let hash = internal_hash(key);
    for level in 0..=17 {
        if bits(node) & 3 == 1 {
            // SAFETY: a HAMT leaf is a live cons.
            let (candidate, value) = unsafe { node.cons_ref().unwrap() };
            return Ok(exact_eq(candidate, key).then_some(value));
        }
        let h = node.header().unwrap();
        if h & 63 == 0 {
            // SAFETY: a collision tuple contains tagged leaf terms.
            unsafe {
                let p = node.raw_ptr();
                for i in 0..(h >> 6) as usize {
                    let leaf = term(*p.add(1 + i));
                    let (candidate, value) = leaf.cons_ref().unwrap();
                    if exact_eq(candidate, key) {
                        return Ok(Some(value));
                    }
                }
            }
            return Ok(None);
        }
        if level == 17 {
            return Ok(None);
        }
        let bitmap = ((h >> 16) & 0xffff) as u16;
        let bit = 1u16 << slot(hash, level);
        if bitmap & bit == 0 {
            return Ok(None);
        }
        let index = (bitmap & (bit - 1)).count_ones() as usize;
        let offset = if (h >> 6) & 3 >= 2 { 2 } else { 1 };
        // SAFETY: the bitmap selects an initialized child of the live node.
        node = unsafe { term(*node.raw_ptr().add(offset + index)) };
    }
    Ok(None)
}

/// `maps:find/2` value lookup.
pub fn find(map: Term, key: Term) -> MapResult<Option<Term>> {
    // Port of erts/emulator/beam/erl_map.c:2055-2101, OTP-29.1.1.
    get(map, key)
}
/// `maps:is_key/2`.
pub fn is_key(map: Term, key: Term) -> MapResult<bool> {
    Ok(get(map, key)?.is_some())
}

fn change<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    value: Option<Term>,
    exact: bool,
    heap: &mut H,
) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:2036-2235, OTP-29.1.1.
    check(map)?;
    if !map.is_hashmap() {
        // SAFETY: the map heap remains live during this operation.
        let view = unsafe { map.flatmap_ref().unwrap() };
        let found = view.iter().position(|(k, _)| exact_eq(k, key));
        if exact && found.is_none() {
            return Err(MapError::Badkey(key));
        }
        if let (Some(i), Some(v)) = (found, value) {
            return if view.iter().nth(i).unwrap().1 == v {
                Ok(map)
            } else {
                flat_replace(map, i, v, heap)
            };
        }
        let mut pairs: Vec<_> = view.iter().collect();
        match (found, value) {
            (Some(i), None) => {
                pairs.remove(i);
            }
            (None, Some(v)) => {
                pairs.push((key, v));
            }
            (None, None) => return Ok(map),
            (Some(_), Some(_)) => unreachable!(),
        }
        if pairs.len() <= LIMIT {
            pairs.sort_by(|a, b| key_cmp(a.0, b.0));
            return flat(&pairs, heap);
        }
        let entries = unique(&pairs);
        return build_hamt(&entries, heap);
    }
    if let Some(value) = value {
        return hashmap_insert(map, key, value, exact, heap);
    }
    let n = size(map)?;
    if n == LIMIT + 1 {
        if get(map, key)?.is_none() {
            return Ok(map);
        }
        // Port of erts/emulator/beam/erl_map.c:2975-3025 (hashmap_delete), OTP-29.1.1.
        let mut pairs: Vec<_> = iter(map)?.filter(|(k, _)| !exact_eq(*k, key)).collect();
        pairs.sort_by(|a, b| key_cmp(a.0, b.0));
        return flat(&pairs, heap);
    }
    hashmap_delete(map, key, heap)
}
/// `Map#{Key => Value}` / `maps:put/3`.
pub fn put<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    value: Term,
    heap: &mut H,
) -> MapResult<Term> {
    change(map, key, Some(value), false, heap)
}
/// `Map#{Key := Value}` / `maps:update/3`.
pub fn update<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    value: Term,
    heap: &mut H,
) -> MapResult<Term> {
    change(map, key, Some(value), true, heap)
}
/// `maps:remove/2`.
pub fn remove<H: HeapAlloc + ?Sized>(map: Term, key: Term, heap: &mut H) -> MapResult<Term> {
    change(map, key, None, false, heap)
}
/// Apply instruction key-value updates; exact mode rejects missing keys.
pub fn put_many<H: HeapAlloc + ?Sized>(
    map: Term,
    pairs: &[(Term, Term)],
    exact: bool,
    heap: &mut H,
) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:261-365, OTP-29.1.1.
    let mut sizing = SizingHeap {
        inner: heap,
        requested_words: 0,
    };
    let result = put_many_sized(map, pairs, exact, &mut sizing);
    result.map_err(|error| match error {
        MapError::HeapFull { .. } => MapError::HeapFull {
            need_words: sizing.requested_words,
        },
        error => error,
    })
}

fn put_many_sized<H: HeapAlloc + ?Sized>(
    map: Term,
    pairs: &[(Term, Term)],
    exact: bool,
    heap: &mut H,
) -> MapResult<Term> {
    // Port of erts/emulator/beam/beam_common.c:1960-2328, OTP-29.1.1.
    check(map)?;
    // Port of erts/emulator/beam/emu/ops.tab:1378 (`map_key_sort` for
    // `put_map_exact`), OTP-29.1.1. This order defines the reported missing key.
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|a, b| key_cmp(a.0, b.0));
    if exact {
        for &(key, _) in &sorted {
            if get(map, key)?.is_none() {
                return Err(MapError::Badkey(key));
            }
        }
    }
    // Map instruction updates commonly retain every key and replace only
    // values. Preserve the key tuple and the original map when possible;
    // rebuilding all values through `from_pairs` loses OTP's sharing.
    let unchanged = sorted.iter().enumerate().all(|(index, &(key, value))| {
        if sorted[index + 1..]
            .iter()
            .any(|&(later_key, _)| exact_eq(key, later_key))
        {
            return true;
        }
        get(map, key).ok().flatten() == Some(value)
    });
    if unchanged {
        return Ok(map);
    }
    if !map.is_hashmap()
        && sorted
            .iter()
            .all(|(key, _)| get(map, *key).ok().flatten().is_some())
    {
        // Port of erts/emulator/beam/jit/arm/instr_map.cpp:600-636 and
        // erts/emulator/beam/beam_common.c:2203-2328 (erts_gc_update_map_exact), OTP-29.1.1.
        let mut entries: Vec<_> = iter(map)?.collect();
        for (key, value) in sorted {
            let index = entries
                .binary_search_by(|(candidate, _)| key_cmp(*candidate, key))
                .expect("exact map update key was checked above");
            entries[index].1 = value;
        }
        let keys = map.flatmap_keys_tuple().ok_or(MapError::Badmap(map))?;
        let values: Vec<_> = entries.iter().map(|(_, value)| *value).collect();
        return TermBuilder::new(heap)
            .flatmap_with_key_tuple(keys, &values)
            .map_err(|error| match error {
                TermError::HeapFull => MapError::HeapFull {
                    need_words: 3 + values.len(),
                },
                _ => MapError::Badmap(map),
            });
    }
    let mut result = map;
    let mut entries = to_list(result)?;
    entries.extend_from_slice(&sorted);
    result = from_pairs(&entries, heap)?;
    Ok(result)
}
/// Build a map from pairs; the last value for a key wins.
pub fn from_pairs<H: HeapAlloc + ?Sized>(pairs: &[(Term, Term)], heap: &mut H) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:644-827, OTP-29.1.1.
    let entries = unique(pairs);
    if entries.len() <= LIMIT {
        flat(&entries, heap)
    } else {
        build_hamt(&entries, heap)
    }
}
/// Build an empty flatmap.
pub fn new<H: HeapAlloc + ?Sized>(heap: &mut H) -> MapResult<Term> {
    flat(&[], heap)
}
/// Iterate entries in the order of `maps:to_list/1`.
pub fn iter(map: Term) -> MapResult<MapIter> {
    // Port of erts/emulator/beam/erl_map.c:2320-2410, OTP-29.1.1.
    check(map)?;
    let mut entries = Vec::with_capacity(size(map)?);
    if map.is_hashmap() {
        collect(map, &mut entries);
    } else {
        // SAFETY: the owning heap remains live while the view is read.
        entries.extend(unsafe { map.flatmap_ref().unwrap() }.iter());
    }
    Ok(MapIter {
        entries: entries.into_iter(),
    })
}
/// Iterator valid while the source heap is live.
pub struct MapIter {
    entries: std::vec::IntoIter<(Term, Term)>,
}
impl Iterator for MapIter {
    type Item = (Term, Term);
    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }
}
/// `maps:to_list/1` pairs in native iteration order.
pub fn to_list(map: Term) -> MapResult<Vec<(Term, Term)>> {
    Ok(iter(map)?.collect())
}
/// Pair order used by ordinary `term_to_binary/1` map encoding.
/// HAMT pairs are reversed because `external.c` pushes children onto a LIFO stack.
pub fn term_to_binary_pairs(map: Term) -> MapResult<Vec<(Term, Term)>> {
    // Port of erts/emulator/beam/erl_map.c:238-267, OTP-29.1.1.
    // Port of erts/emulator/beam/external.c:3745-3822 (MAP_DEF), OTP-29.1.1.
    let mut pairs = to_list(map)?;
    if map.is_hashmap() {
        pairs.reverse();
    }
    Ok(pairs)
}
/// `maps:keys/1` in native iteration order.
pub fn keys(map: Term) -> MapResult<Vec<Term>> {
    Ok(iter(map)?.map(|(k, _)| k).collect())
}
/// `maps:values/1` in native iteration order.
pub fn values(map: Term) -> MapResult<Vec<Term>> {
    Ok(iter(map)?.map(|(_, v)| v).collect())
}
/// Lookup several keys; absent keys return `None`.
pub fn get_many(map: Term, keys: &[Term]) -> MapResult<Vec<Option<Term>>> {
    check(map)?;
    keys.iter().map(|key| get(map, *key)).collect()
}

fn none_atom() -> Term {
    Term::atom(
        global_atoms()
            .intern("none")
            .expect("OTP predefined atom fits"),
    )
}

/// `maps:iterator/1` or `maps:iterator/2` with `ordered = true`.
/// The initial terms are `[0 | Map]` and `[SortedKeys | Map]` respectively.
pub fn iterator_term<H: HeapAlloc + ?Sized>(
    map: Term,
    ordered: bool,
    heap: &mut H,
) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:3620-3744, OTP-29.1.1.
    iterator_term_order(map, if ordered { Some(false) } else { None }, heap)
}

/// `maps:iterator(Map, reversed)` with descending exact term order.
pub fn iterator_term_reversed<H: HeapAlloc + ?Sized>(map: Term, heap: &mut H) -> MapResult<Term> {
    iterator_term_order(map, Some(true), heap)
}

fn iterator_term_order<H: HeapAlloc + ?Sized>(
    map: Term,
    ordered: Option<bool>,
    heap: &mut H,
) -> MapResult<Term> {
    check(map)?;
    let mut keys = if ordered.is_some() {
        keys(map)?
    } else {
        Vec::new()
    };
    if let Some(reverse) = ordered {
        keys.sort_by(|a, b| exact_cmp(*a, *b, false));
        if reverse {
            keys.reverse();
        }
    }
    let need_words = 2 + 2 * keys.len();
    let mut p = heap
        .alloc(need_words)
        .ok_or(MapError::HeapFull { need_words })?;
    let mut path = if ordered.is_some() {
        Term::NIL
    } else {
        Term::small(0).unwrap()
    };
    for key in keys.into_iter().rev() {
        // SAFETY: one allocation reserves every two-word list cell.
        unsafe {
            *p = bits(key);
            *p.add(1) = bits(path);
            p = p.add(2);
        }
        // SAFETY: p advanced by two words inside this same allocation.
        path = cons(unsafe { p.sub(2) });
    }
    // SAFETY: the last two words are reserved for the improper list cell.
    unsafe {
        *p = bits(path);
        *p.add(1) = bits(map);
    }
    Ok(cons(p))
}

fn collect_paths(node: Term, prefix: u128, level: usize, out: &mut Vec<(u128, Term, Term)>) {
    if bits(node) & 3 == 1 {
        // SAFETY: a live HAMT leaf is a two-word cons.
        let (key, value) = unsafe { node.cons_ref().unwrap() };
        out.push((prefix, key, value));
        return;
    }
    if node.header().is_some_and(|h| h & 63 == 0) {
        for (i, Tree::Old(child)) in collision_children(node).into_iter().enumerate() {
            collect_paths(child, prefix | ((i as u128) << (4 * level)), level + 1, out);
        }
    } else {
        for (i, (_, Tree::Old(child))) in children(node).into_iter().enumerate() {
            collect_paths(child, prefix | ((i as u128) << (4 * level)), level + 1, out);
        }
    }
}

fn native_path(path: Term) -> Option<u128> {
    if let Some(value) = path.as_small() {
        return (value >= 0).then_some(value as u128);
    }
    let h = path.header()?;
    if h & 63 != 0x08 || !(1..=2).contains(&(h >> 6)) {
        return None;
    }
    // SAFETY: a positive bignum header of one or two digits bounds both reads.
    unsafe {
        let p = path.raw_ptr();
        Some(
            *p.add(1) as u128
                | if h >> 6 == 2 {
                    (*p.add(2) as u128) << 64
                } else {
                    0
                },
        )
    }
}

enum NextPath {
    Native(u128),
    Ordered(Term),
}

/// `maps:next/1` on an iterator term. Returns `none` at exhaustion.
/// Flatmap and ordered paths build a tuple chain; HAMT paths return one pair.
pub fn next_term<H: HeapAlloc + ?Sized>(iterator: Term, heap: &mut H) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:3620-3744, OTP-29.1.1.
    if iterator == none_atom() {
        return Ok(iterator);
    }
    if iterator.classify() == TermKind::Tuple {
        // SAFETY: a live tuple exposes its arity and elements.
        if unsafe { iterator.tuple_ref().unwrap() }.len() == 3 {
            return Ok(iterator);
        }
    }
    // SAFETY: a valid iterator is an improper cons with a map tail.
    let (path, map) = unsafe { iterator.cons_ref() }.ok_or(MapError::Badarg(iterator))?;
    if check(map).is_err() {
        return Err(MapError::Badarg(iterator));
    }
    if !map.is_hashmap()
        && let Some(index) = native_path(path)
    {
        let entries = to_list(map)?;
        if index > entries.len() as u128 {
            return Err(MapError::Badarg(iterator));
        }
        if entries.is_empty() {
            return Ok(none_atom());
        }
        let need_words = 4 * entries.len();
        let p = heap
            .alloc(need_words)
            .ok_or(MapError::HeapFull { need_words })?;
        let mut result = none_atom();
        for (i, (key, value)) in entries.into_iter().rev().enumerate() {
            // SAFETY: one allocation reserves a three-element tuple per pair.
            unsafe {
                let t = p.add(4 * i);
                *t = 3 << 6;
                *t.add(1) = bits(key);
                *t.add(2) = bits(value);
                *t.add(3) = bits(result);
                result = boxed(t);
            }
        }
        return Ok(result);
    }
    if path == Term::NIL {
        return Ok(none_atom());
    }
    if path.classify() == TermKind::List {
        let mut keys = path;
        let mut entries = Vec::new();
        while keys.classify() == TermKind::List {
            // SAFETY: an ordered iterator path is a live proper list.
            let (key, tail) = unsafe { keys.cons_ref().unwrap() };
            entries.push((key, get(map, key)?.ok_or(MapError::Badarg(iterator))?));
            keys = tail;
        }
        if keys != Term::NIL {
            return Err(MapError::Badarg(iterator));
        }
        let need_words = 4 * entries.len();
        let p = heap
            .alloc(need_words)
            .ok_or(MapError::HeapFull { need_words })?;
        let mut result = none_atom();
        for (i, (key, value)) in entries.into_iter().rev().enumerate() {
            // SAFETY: one allocation reserves a three-element tuple per pair.
            unsafe {
                let t = p.add(4 * i);
                *t = 3 << 6;
                *t.add(1) = bits(key);
                *t.add(2) = bits(value);
                *t.add(3) = bits(result);
                result = boxed(t);
            }
        }
        return Ok(result);
    }
    let (key, value, next_path) = if let Some(path) = native_path(path) {
        let mut entries = Vec::with_capacity(size(map)?);
        if map.is_hashmap() {
            collect_paths(map, 0, 0, &mut entries);
        } else {
            entries.extend(iter(map)?.enumerate().map(|(i, (k, v))| (i as u128, k, v)));
        }
        if entries.is_empty() && path == 0 {
            return Ok(none_atom());
        }
        let at = entries
            .iter()
            .position(|(p, _, _)| *p == path)
            .ok_or(MapError::Badarg(iterator))?;
        let (_, key, value) = entries[at];
        (
            key,
            value,
            entries.get(at + 1).map(|(p, _, _)| NextPath::Native(*p)),
        )
    } else {
        if path == Term::NIL {
            return Ok(none_atom());
        }
        // SAFETY: ordered iterator path is a live proper list of keys.
        let (key, tail) = unsafe { path.cons_ref() }.ok_or(MapError::Badarg(iterator))?;
        let value = get(map, key)?.ok_or(MapError::Badarg(iterator))?;
        (key, value, Some(NextPath::Ordered(tail)))
    };
    let extra = match &next_path {
        Some(NextPath::Native(path)) if *path > arinsal_term::MAX_SMALL as u128 => {
            1 + if *path > u64::MAX as u128 { 2 } else { 1 }
        }
        _ => 0,
    };
    let need_words = 4 + if next_path.is_some() { 2 + extra } else { 0 };
    let p = heap
        .alloc(need_words)
        .ok_or(MapError::HeapFull { need_words })?;
    // SAFETY: the allocation reserves a three-element tuple and optional cons.
    unsafe {
        *p = 3 << 6;
        *p.add(1) = bits(key);
        *p.add(2) = bits(value);
        if let Some(path) = next_path {
            let (path, tail) = match path {
                NextPath::Ordered(path) => (path, p.add(4)),
                NextPath::Native(path) if extra == 0 => {
                    (Term::small(path as i64).unwrap(), p.add(4))
                }
                NextPath::Native(path) => {
                    let big = p.add(4);
                    *big = ((extra - 1) as u64) << 6 | 0x08;
                    *big.add(1) = path as u64;
                    if extra == 3 {
                        *big.add(2) = (path >> 64) as u64;
                    }
                    (boxed(big), big.add(extra))
                }
            };
            *tail = bits(path);
            *tail.add(1) = bits(map);
            *p.add(3) = bits(cons(tail));
        } else {
            *p.add(3) = bits(none_atom());
        }
    }
    Ok(boxed(p))
}
