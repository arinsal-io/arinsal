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
    HeapAlloc, Term, TermError, TermKind, cmp, exact_eq, global_atoms, internal_hash,
};
use std::cmp::Ordering;

mod merge;
pub use merge::{
    HashmapFromPairs, HashmapMergeContext, MAP_MERGE_LOOP_FACTOR, MergeStart, from_keys, from_list,
    from_small_pairs, hashmap_merge, merge, merge_start,
};

const MAP: u64 = 0x2c;
const LIMIT: usize = 32;

/// Map operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// `{badmap, Term}`.
    Badmap(Term),
    /// `{badkey, Key}`.
    Badkey(Term),
    /// Caller must collect garbage and retry; `0` means the operation has no whole-operation hint.
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
    slice[2].write(bits(arinsal_term::global_empty_tuple()));
    Ok(boxed(ptr))
}

fn build_hamt<H: HeapAlloc + ?Sized>(pairs: &[(Term, Term)], heap: &mut H) -> MapResult<Term> {
    // Port of erts/emulator/beam/erl_map.c:712-759 (erts_hashmap_from_ks_and_vs_extra), OTP-29.1.1.
    merge::allocation_result(arinsal_term::build_hamt_from_unique(pairs, heap))
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
fn hashmap_delete<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    heap: &mut H,
    value: &mut Option<Term>,
) -> MapResult<Term> {
    const NONE: u8 = 0;
    const LEAF: u8 = 1;
    const BOXED: u8 = 2;
    if map.is_hashmap()
        && size(map)? == LIMIT + 1
        && let Some(found) = get(map, key)?
    {
        *value = Some(found);
        let mut pairs: Vec<_> = iter(map)?
            .filter(|(candidate, _)| !exact_eq(*candidate, key))
            .collect();
        pairs.sort_by(|a, b| key_cmp(a.0, b.0));
        return flat(&pairs, heap);
    }
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
                *value = Some(term(*leaf.add(1)));
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
                *value = Some(term(*term(*source.add(1 + index)).raw_ptr().add(1)));
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
#[inline]
pub fn get(map: Term, key: Term) -> MapResult<Option<Term>> {
    check(map)?;
    Ok(lookup(map, key))
}

/// Looks `key` up in a checked map.
// Port of erts/emulator/beam/erl_map.c:2424-2474 (erts_maps_get returns the value's address,
// NULL when absent), OTP-29.1.1: the result comes back in registers.
fn lookup(map: Term, key: Term) -> Option<Term> {
    if !map.is_hashmap() {
        // SAFETY: the source heap remains live during this operation.
        return unsafe { map.flatmap_ref().unwrap() }.get(key);
    }
    let mut node = map;
    let hash = internal_hash(key);
    // SAFETY: every node reached from the live root is a live HAMT node, collision
    // tuple or leaf cons; the bitmap selects an initialized child.
    unsafe {
        for level in 0..=17 {
            if bits(node) & 3 == 1 {
                let (candidate, value) = node.cons_ref().unwrap();
                return exact_eq(candidate, key).then_some(value);
            }
            let h = node.header().unwrap();
            if h & 63 == 0 {
                let p = node.raw_ptr();
                for i in 0..(h >> 6) as usize {
                    let leaf = term(*p.add(1 + i));
                    let (candidate, value) = leaf.cons_ref().unwrap();
                    if exact_eq(candidate, key) {
                        return Some(value);
                    }
                }
                return None;
            }
            if level == 17 {
                return None;
            }
            let bitmap = ((h >> 16) & 0xffff) as u16;
            let bit = 1u16 << slot(hash, level);
            if bitmap & bit == 0 {
                return None;
            }
            let index = (bitmap & (bit - 1)).count_ones() as usize;
            let offset = if (h >> 6) & 3 >= 2 { 2 } else { 1 };
            node = term(*node.raw_ptr().add(offset + index));
        }
    }
    None
}

/// `maps:find/2` value lookup.
#[inline]
pub fn find(map: Term, key: Term) -> MapResult<Option<Term>> {
    // Port of erts/emulator/beam/erl_map.c:2055-2101, OTP-29.1.1.
    get(map, key)
}
/// `maps:is_key/2`.
pub fn is_key(map: Term, key: Term) -> MapResult<bool> {
    Ok(get(map, key)?.is_some())
}

/// `maps:remove/2`.
pub fn remove<H: HeapAlloc + ?Sized>(map: Term, key: Term, heap: &mut H) -> MapResult<Term> {
    Ok(maps_take(map, key, heap)?.map_or(map, |(_, map)| map))
}

/// `maps:take/2`: the value under `key` and the map without it, or `None` when absent.
pub fn take<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    heap: &mut H,
) -> MapResult<Option<(Term, Term)>> {
    maps_take(map, key, heap)
}

// Port of erts/emulator/beam/erl_map.c:1943-2041 (erts_maps_take), OTP-29.1.1.
fn maps_take<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    heap: &mut H,
) -> MapResult<Option<(Term, Term)>> {
    check(map)?;
    if !map.is_hashmap() {
        return flatmap_take(map, key, heap);
    }
    let mut value = None;
    let res = hashmap_delete(map, key, heap, &mut value)?;
    Ok(value.map(|value| (value, res)))
}

/// The flatmap branch of `erts_maps_take`: one pass that assumes the key exists, copying the
/// other keys and values as it searches, and releases the output when it does not.
// Port of erts/emulator/beam/erl_map.c:1947-2033 (erts_maps_take), OTP-29.1.1.
fn flatmap_take<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    heap: &mut H,
) -> MapResult<Option<(Term, Term)>> {
    let (ks, vs, _) = merge::flatmap_kv(map);
    let n = ks.len();
    if n == 0 {
        return Ok(None);
    }
    let tuple_words = if n == 1 { 0 } else { n };
    let need_words = tuple_words + FLATMAP_HEADER_WORDS + n - 1;
    let (output, start) =
        merge::produce(heap, need_words).map_err(|_| MapError::HeapFull { need_words })?;
    let (tuple, rest) = output.split_at_mut(tuple_words);
    let (header, values) = rest.split_at_mut(FLATMAP_HEADER_WORDS);
    let found = if is_immed(key) {
        let key = bits(key);
        ks.iter().position(|&k| k == key)
    } else {
        ks.iter().position(|&k| exact_eq(term(k), key))
    };
    let Some(found) = found else {
        heap.release(start.wrapping_add(need_words), start);
        return Ok(None);
    };
    let keys = if n == 1 {
        arinsal_term::global_empty_tuple()
    } else {
        tuple[0].write(((n - 1) as u64) << 6);
        copy_skipping(&mut tuple[1..], ks, found);
        boxed(start)
    };
    copy_skipping(values, vs, found);
    header[0].write(MAP);
    header[1].write((n - 1) as u64);
    header[2].write(bits(keys));
    // The map header follows the key tuple inside the allocated block.
    let res = boxed(start.wrapping_add(tuple_words));
    Ok(Some((term(vs[found]), res)))
}

/// One `erts_internal:map_next/3` step over a whole flatmap: the `{K, V, Next}` chain ending
/// in `none` (`list_mode == false`), or `[{K, V} | Acc]` for every association.
// Port of erts/emulator/beam/erl_map.c:3710-3735 (erts_internal_map_next_3), OTP-29.1.1.
pub fn flatmap_next<H: HeapAlloc + ?Sized>(
    map: Term,
    list_mode: bool,
    acc: Term,
    heap: &mut H,
) -> MapResult<Term> {
    let (ks, vs, _) = merge::flatmap_kv(map);
    let n = ks.len();
    let per_elem = if list_mode { 5 } else { 4 };
    let need_words = per_elem * n;
    let (output, start) =
        merge::produce(heap, need_words).map_err(|_| MapError::HeapFull { need_words })?;
    let mut res = if list_mode { acc } else { none_atom() };
    for (index, words) in output.chunks_exact_mut(per_elem).enumerate() {
        let from = n - 1 - index;
        let at = start.wrapping_add(per_elem * index);
        if list_mode {
            words[0].write(2 << 6);
            words[1].write(ks[from]);
            words[2].write(vs[from]);
            words[3].write(bits(boxed(at)));
            words[4].write(bits(res));
            res = cons(at.wrapping_add(3));
        } else {
            words[0].write(3 << 6);
            words[1].write(ks[from]);
            words[2].write(vs[from]);
            words[3].write(bits(res));
            res = boxed(at);
        }
    }
    Ok(res)
}

/// `[{Key, Value} | Tail]`, the list-mode element of `erts_internal:map_next/3`: a 2-tuple
/// followed by its cons cell in one 5-word block.
// Port of erts/emulator/beam/erl_map.c:3733-3734 and :4002-4003 (TUPLE2 then CONS),
// OTP-29.1.1.
#[inline]
pub fn cons_pair<H: HeapAlloc + ?Sized>(
    heap: &mut H,
    key: Term,
    value: Term,
    tail: Term,
) -> MapResult<Term> {
    let (words, at) = merge::produce(heap, 5).map_err(|_| MapError::HeapFull { need_words: 5 })?;
    words[0].write(2 << 6);
    words[1].write(bits(key));
    words[2].write(bits(value));
    words[3].write(bits(boxed(at)));
    words[4].write(bits(tail));
    Ok(cons(at.wrapping_add(3)))
}

/// `source` without its element at `skip`, into `out` (one word shorter).
fn copy_skipping(out: &mut [std::mem::MaybeUninit<u64>], source: &[u64], skip: usize) {
    let (before, after) = out.split_at_mut(skip);
    for (slot, &word) in before.iter_mut().zip(&source[..skip]) {
        slot.write(word);
    }
    for (slot, &word) in after.iter_mut().zip(&source[skip + 1..]) {
        slot.write(word);
    }
}

// erts MAP_HEADER_FLATMAP_SZ: header, size, key tuple.
const FLATMAP_HEADER_WORDS: usize = 3;
const POS_BIG_SUBTAG: u64 = 0x08;

fn is_immed(t: Term) -> bool {
    bits(t) & 3 == 3
}

/// Covers `[start, end)` with a heap filler and gives it back to the allocator; used
/// inside the callers' unsafe blocks.
// Port of erts/emulator/beam/erl_vm.h:164-173 (HRelease) and erl_term.h:1500-1504
// (erts_write_heap_filler), OTP-29.1.1.
macro_rules! release {
    ($heap:expr, $end:expr, $start:expr) => {{
        let (end, start): (*mut u64, *mut u64) = ($end, $start);
        let words = (end as usize).saturating_sub(start as usize) / 8;
        if words > 0 {
            start.write(((words as u64 - 1) << 6) | POS_BIG_SUBTAG);
            HeapAlloc::release($heap, end, start);
        }
    }};
}

/// Builds the HAMT for a flatmap that outgrew `MAP_SMALL_MAP_LIMIT`, plus an extra pair.
// Port of erts/emulator/beam/erl_map.c:712-759 (erts_hashmap_from_ks_and_vs_extra), OTP-29.1.1.
fn hashmap_from_ks_and_vs_extra<H: HeapAlloc + ?Sized>(
    ks: &[Term],
    vs: &[Term],
    extra: Option<(Term, Term)>,
    heap: &mut H,
) -> MapResult<Term> {
    merge::allocation_result(
        arinsal_term::hashmap_from_ks_and_vs_extra(ks, vs, extra, false, heap)
            .map(|map| map.expect("duplicates accepted")),
    )
}

/// The keys and values of a live flatmap as slices.
// Port of erts/emulator/beam/erl_map.h:92-102 (flatmap_get_keys, flatmap_get_values),
// OTP-29.1.1; used inside the callers' unsafe blocks.
macro_rules! flatmap_slices {
    ($ks:expr, $vs:expr, $n:expr) => {{
        let (ks, vs, n): (*const u64, *const u64, usize) = ($ks, $vs, $n);
        (
            std::slice::from_raw_parts(ks.cast::<Term>(), n),
            std::slice::from_raw_parts(vs.cast::<Term>(), n),
        )
    }};
}

/// `Map#{Key => Value}` / `maps:put/3`.
// Port of erts/emulator/beam/erl_map.c:2105-2232 (erts_maps_put), OTP-29.1.1.
pub fn put<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    value: Term,
    heap: &mut H,
) -> MapResult<Term> {
    check(map)?;
    if map.is_hashmap() {
        return hashmap_insert(map, key, value, false, heap);
    }
    // SAFETY: check() established a live flatmap; every write stays inside the
    // allocations made here, whose sizes are computed from the flatmap size.
    unsafe {
        let mp = map.raw_ptr();
        let n = *mp.add(1) as usize;
        if n == 0 {
            let need_words = FLATMAP_HEADER_WORDS + 1 + 2;
            let hp = heap
                .alloc(need_words)
                .ok_or(MapError::HeapFull { need_words })?;
            *hp = 1 << 6;
            *hp.add(1) = bits(key);
            let m = hp.add(2);
            *m = MAP;
            *m.add(1) = 1;
            *m.add(2) = bits(boxed(hp));
            *m.add(3) = bits(value);
            return Ok(boxed(m));
        }
        let ks = term(*mp.add(2)).raw_ptr().add(1);
        let vs = mp.add(FLATMAP_HEADER_WORDS);

        // Only allocate for values, assuming the key tuple stays intact.
        let first = FLATMAP_HEADER_WORDS + n;
        let shp = heap.alloc(first).ok_or(MapError::HeapFull {
            need_words: first + FLATMAP_HEADER_WORDS + n + 1,
        })?;
        *shp = MAP;
        *shp.add(1) = n as u64;
        *shp.add(2) = *mp.add(2);
        let hp = shp.add(FLATMAP_HEADER_WORDS);
        let raw_key = bits(key);
        let immed = is_immed(key);
        let mut i = 0;
        while i < n {
            let candidate = *ks.add(i);
            if candidate == raw_key || (!immed && exact_eq(term(candidate), key)) {
                if *vs.add(i) == bits(value) {
                    release!(heap, shp.add(first), shp);
                    return Ok(map);
                }
                *hp.add(i) = bits(value);
                std::ptr::copy_nonoverlapping(vs.add(i + 1), hp.add(i + 1), n - i - 1);
                return Ok(boxed(shp));
            }
            *hp.add(i) = *vs.add(i);
            i += 1;
        }

        // The map grows.
        if n >= LIMIT {
            release!(heap, shp.add(first), shp);
            let (ks, vs) = flatmap_slices!(ks, vs, n);
            return hashmap_from_ks_and_vs_extra(ks, vs, Some((key, value)), heap);
        }
        // Still a small map: the new key tuple reuses the first allocation.
        let second = FLATMAP_HEADER_WORDS + n + 1;
        let Some(hp) = heap.alloc(second) else {
            release!(heap, shp.add(first), shp);
            return Err(MapError::HeapFull {
                need_words: first + second,
            });
        };
        *shp = ((n + 1) as u64) << 6;
        *hp = MAP;
        *hp.add(1) = (n + 1) as u64;
        *hp.add(2) = bits(boxed(shp));
        let mut kp = shp.add(1);
        let mut vp = hp.add(FLATMAP_HEADER_WORDS);
        let mut i = 0;
        while i < n && key_cmp(term(*ks.add(i)), key) == Ordering::Less {
            *kp = *ks.add(i);
            *vp = *vs.add(i);
            kp = kp.add(1);
            vp = vp.add(1);
            i += 1;
        }
        *kp = raw_key;
        *vp = bits(value);
        kp = kp.add(1);
        vp = vp.add(1);
        std::ptr::copy_nonoverlapping(ks.add(i), kp, n - i);
        std::ptr::copy_nonoverlapping(vs.add(i), vp, n - i);
        // One word of the first allocation remains.
        *kp.add(n - i) = POS_BIG_SUBTAG;
        Ok(boxed(hp))
    }
}

/// `Map#{Key := Value}` / `maps:update/3`; `Badkey` when the key is absent.
// Port of erts/emulator/beam/erl_map.c:2036-2103 (erts_maps_update), OTP-29.1.1.
pub fn update<H: HeapAlloc + ?Sized>(
    map: Term,
    key: Term,
    value: Term,
    heap: &mut H,
) -> MapResult<Term> {
    check(map)?;
    if map.is_hashmap() {
        return hashmap_insert(map, key, value, true, heap);
    }
    // SAFETY: check() established a live flatmap; writes stay inside the one
    // allocation of header plus n values.
    unsafe {
        let mp = map.raw_ptr();
        let n = *mp.add(1) as usize;
        if n == 0 {
            return Err(MapError::Badkey(key));
        }
        let ks = term(*mp.add(2)).raw_ptr().add(1);
        let vs = mp.add(FLATMAP_HEADER_WORDS);
        let need_words = FLATMAP_HEADER_WORDS + n;
        let shp = heap
            .alloc(need_words)
            .ok_or(MapError::HeapFull { need_words })?;
        *shp = MAP;
        *shp.add(1) = n as u64;
        *shp.add(2) = *mp.add(2);
        let hp = shp.add(FLATMAP_HEADER_WORDS);
        let raw_key = bits(key);
        let immed = is_immed(key);
        for i in 0..n {
            let candidate = *ks.add(i);
            if candidate == raw_key || (!immed && exact_eq(term(candidate), key)) {
                if *vs.add(i) == bits(value) {
                    release!(heap, shp.add(need_words), shp);
                    return Ok(map);
                }
                *hp.add(i) = bits(value);
                std::ptr::copy_nonoverlapping(vs.add(i + 1), hp.add(i + 1), n - i - 1);
                return Ok(boxed(shp));
            }
            *hp.add(i) = *vs.add(i);
        }
        release!(heap, shp.add(need_words), shp);
        Err(MapError::Badkey(key))
    }
}

/// Heap words `erts_gc_new_map` requires before building from `n` vector entries.
pub fn new_map_need(n: usize) -> usize {
    if n > 2 * LIMIT { n } else { n + 4 }
}

/// Builds a map from a sorted key/value vector of `n` entries; `arg(i)` reads entry `i`.
// Port of erts/emulator/beam/beam_common.c:1863-1925 (erts_gc_new_map), OTP-29.1.1. The
// caller collects first when fewer than `new_map_need(n)` words are left.
pub fn gc_new_map<H: HeapAlloc + ?Sized>(
    n: usize,
    arg: impl Fn(usize) -> Term,
    heap: &mut H,
) -> MapResult<Term> {
    let pairs = n / 2;
    if n > 2 * LIMIT {
        // erts_hashmap_from_array with reject_dupkeys = 0: the last duplicate wins.
        let entries: Vec<_> = (0..pairs).map(|i| (arg(2 * i), arg(2 * i + 1))).collect();
        return from_pairs(&entries, heap);
    }
    if n == 0 {
        return flat(&[], heap);
    }
    let need_words = n + 4;
    let thp = heap
        .alloc(need_words)
        .ok_or(MapError::HeapFull { need_words })?;
    // SAFETY: the allocation holds the key tuple, the flatmap header and the values.
    unsafe {
        *thp = (pairs as u64) << 6;
        let mp = thp.add(1 + pairs);
        *mp = MAP;
        *mp.add(1) = pairs as u64;
        *mp.add(2) = bits(boxed(thp));
        for i in 0..pairs {
            *thp.add(1 + i) = bits(arg(2 * i));
            *mp.add(FLATMAP_HEADER_WORDS + i) = bits(arg(2 * i + 1));
        }
        Ok(boxed(mp))
    }
}

/// Heap words `erts_gc_update_map_assoc` requires before updating `map` with `n` entries.
pub fn update_map_assoc_need(map: Term, n: usize) -> usize {
    if map.classify() != TermKind::Map || map.is_hashmap() {
        return 0;
    }
    let num_old = size(map).unwrap_or(0);
    if num_old == 0 {
        new_map_need(n)
    } else {
        2 * (num_old + n / 2) + 1 + FLATMAP_HEADER_WORDS
    }
}

/// Associative update of `map` with a key-sorted vector of `n` entries.
// Port of erts/emulator/beam/beam_common.c:1959-2193 (erts_gc_update_map_assoc),
// OTP-29.1.1. The caller collects first when fewer than `update_map_assoc_need` words are
// left; the hashmap path allocates like `HAlloc`.
pub fn gc_update_map_assoc<H: HeapAlloc + ?Sized>(
    map: Term,
    n: usize,
    arg: impl Fn(usize) -> Term,
    heap: &mut H,
) -> MapResult<Term> {
    check(map)?;
    let num_updates = n / 2;
    if map.is_hashmap() {
        let mut res = map;
        for i in 0..num_updates {
            res = hashmap_insert(res, arg(2 * i), arg(2 * i + 1), false, heap)?;
        }
        return Ok(res);
    }
    // SAFETY: check() established a live flatmap. The allocation covers the worst case
    // (every update key is new): header, num_old + num_updates values, key tuple.
    unsafe {
        let old_mp = map.raw_ptr();
        let num_old = *old_mp.add(1) as usize;
        if num_old == 0 {
            return gc_new_map(n, arg, heap);
        }
        let need_words = 2 * (num_old + num_updates) + 1 + FLATMAP_HEADER_WORDS;
        let mp = heap
            .alloc(need_words)
            .ok_or(MapError::HeapFull { need_words })?;
        let end = mp.add(need_words);
        *mp = MAP;
        let mut hp = mp.add(FLATMAP_HEADER_WORDS);
        let tuple = hp.add(num_old + num_updates);
        *mp.add(2) = bits(boxed(tuple));
        let mut kp = tuple.add(1);
        let mut old_vals: *const u64 = old_mp.add(FLATMAP_HEADER_WORDS);
        let mut old_keys: *const u64 = term(*old_mp.add(2)).raw_ptr().add(1);
        let mut old_left = num_old;
        let mut next = 0;
        let mut new_key = arg(0);
        let mut left = num_updates;
        let mut changed_keys = false;
        let mut changed_values = false;
        loop {
            let key = *old_keys;
            let c = if key == bits(new_key) {
                Ordering::Equal
            } else {
                key_cmp(term(key), new_key)
            };
            if c == Ordering::Less {
                *kp = key;
                *hp = *old_vals;
                kp = kp.add(1);
                hp = hp.add(1);
                old_keys = old_keys.add(1);
                old_vals = old_vals.add(1);
                old_left -= 1;
            } else {
                *hp = bits(arg(next + 1));
                if c == Ordering::Greater {
                    *kp = bits(new_key);
                    changed_keys = true;
                } else {
                    if *old_vals != *hp {
                        changed_values = true;
                    }
                    *kp = key;
                    old_keys = old_keys.add(1);
                    old_vals = old_vals.add(1);
                    old_left -= 1;
                }
                kp = kp.add(1);
                hp = hp.add(1);
                left -= 1;
                if left == 0 {
                    break;
                }
                next += 2;
                new_key = arg(next);
            }
            if old_left == 0 {
                break;
            }
        }
        if left > 0 {
            while left > 0 {
                *kp = bits(arg(next));
                *hp = bits(arg(next + 1));
                kp = kp.add(1);
                hp = hp.add(1);
                next += 2;
                left -= 1;
            }
        } else if !changed_keys && !changed_values {
            release!(heap, end, mp);
            return Ok(map);
        } else if !changed_keys {
            // Only values changed: keep the old key tuple.
            *mp.add(1) = *old_mp.add(1);
            *mp.add(2) = *old_mp.add(2);
            std::ptr::copy_nonoverlapping(old_vals, hp, old_left);
            hp = hp.add(old_left);
            release!(heap, end, hp);
            return Ok(boxed(mp));
        } else {
            std::ptr::copy_nonoverlapping(old_keys, kp, old_left);
            std::ptr::copy_nonoverlapping(old_vals, hp, old_left);
            kp = kp.add(old_left);
            hp = hp.add(old_left);
        }
        // Unused value slots before the key tuple become a filler.
        let gap = (tuple as usize - hp as usize) / 8;
        if gap > 0 {
            *hp = ((gap as u64 - 1) << 6) | POS_BIG_SUBTAG;
        }
        let size = (hp as usize - mp as usize) / 8 - FLATMAP_HEADER_WORDS;
        *mp.add(1) = size as u64;
        *tuple = (size as u64) << 6;
        release!(heap, end, kp);
        if size > LIMIT {
            // erts_hashmap_from_ks_and_vs.
            let (ks, vs) = flatmap_slices!(tuple.add(1), mp.add(FLATMAP_HEADER_WORDS), size);
            return hashmap_from_ks_and_vs_extra(ks, vs, None, heap);
        }
        Ok(boxed(mp))
    }
}

/// Heap words `erts_gc_update_map_exact` requires before updating `map`.
pub fn update_map_exact_need(map: Term) -> usize {
    if map.classify() != TermKind::Map || map.is_hashmap() {
        return 0;
    }
    let num_old = size(map).unwrap_or(0);
    if num_old == 0 {
        0
    } else {
        num_old + FLATMAP_HEADER_WORDS
    }
}

/// Exact update of existing keys of `map` with a key-sorted vector of `n` entries.
// Port of erts/emulator/beam/beam_common.c:2199-2344 (erts_gc_update_map_exact),
// OTP-29.1.1. The caller collects first when fewer than `update_map_exact_need` words are
// left; the hashmap path allocates like `HAlloc`.
pub fn gc_update_map_exact<H: HeapAlloc + ?Sized>(
    map: Term,
    n: usize,
    arg: impl Fn(usize) -> Term,
    heap: &mut H,
) -> MapResult<Term> {
    check(map)?;
    let mut left = n / 2;
    if map.is_hashmap() {
        let mut res = map;
        for i in 0..left {
            res = hashmap_insert(res, arg(2 * i), arg(2 * i + 1), true, heap)?;
        }
        return Ok(res);
    }
    // SAFETY: check() established a live flatmap; the allocation holds the header and
    // exactly num_old values, and the old key tuple is reused.
    unsafe {
        let old_mp = map.raw_ptr();
        let num_old = *old_mp.add(1) as usize;
        if num_old == 0 {
            return Err(MapError::Badkey(arg(0)));
        }
        let need_words = num_old + FLATMAP_HEADER_WORDS;
        let mp = heap
            .alloc(need_words)
            .ok_or(MapError::HeapFull { need_words })?;
        let end = mp.add(need_words);
        *mp = MAP;
        *mp.add(1) = num_old as u64;
        *mp.add(2) = *old_mp.add(2);
        let mut hp = mp.add(FLATMAP_HEADER_WORDS);
        let old_vals = old_mp.add(FLATMAP_HEADER_WORDS);
        let old_keys = term(*old_mp.add(2)).raw_ptr().add(1);
        let mut next = 0;
        let mut new_key = arg(0);
        let mut changed = false;
        for i in 0..num_old {
            if !exact_eq(term(*old_keys.add(i)), new_key) {
                *hp = *old_vals.add(i);
            } else {
                *hp = bits(arg(next + 1));
                if *hp != *old_vals.add(i) {
                    changed = true;
                }
                left -= 1;
                if left == 0 {
                    if !changed {
                        release!(heap, end, mp);
                        return Ok(map);
                    }
                    std::ptr::copy_nonoverlapping(old_vals.add(i + 1), hp.add(1), num_old - i - 1);
                    return Ok(boxed(mp));
                }
                next += 2;
                new_key = arg(next);
            }
            hp = hp.add(1);
        }
        // Updates left: at least one key of the update list does not exist.
        release!(heap, end, mp);
        Err(MapError::Badkey(new_key))
    }
}

/// Apply instruction key-value updates; exact mode rejects missing keys.
///
/// Sorts the pairs like the loader's `map_key_sort` and runs the instruction bodies; a
/// `HeapFull` result asks the caller to collect and retry.
pub fn put_many<H: HeapAlloc + ?Sized>(
    map: Term,
    pairs: &[(Term, Term)],
    exact: bool,
    heap: &mut H,
) -> MapResult<Term> {
    // Port of erts/emulator/beam/beam_transform_helpers.c:54-110 (beam_load_map_key_sort),
    // OTP-29.1.1.
    check(map)?;
    if pairs.is_empty() {
        return Ok(map);
    }
    let mut sorted = pairs.to_vec();
    sorted.sort_by(|a, b| key_cmp(a.0, b.0));
    let arg = |i: usize| {
        let (key, value) = sorted[i / 2];
        if i.is_multiple_of(2) { key } else { value }
    };
    if exact {
        gc_update_map_exact(map, 2 * sorted.len(), arg, heap)
    } else {
        gc_update_map_assoc(map, 2 * sorted.len(), arg, heap)
    }
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
    static NONE: std::sync::OnceLock<Term> = std::sync::OnceLock::new();
    *NONE.get_or_init(|| {
        Term::atom(
            global_atoms()
                .intern("none")
                .expect("OTP predefined atom fits"),
        )
    })
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
