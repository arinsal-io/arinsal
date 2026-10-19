//! Iterative deep copy into one destination allocation.
use crate::literal::LiteralAreas;
use crate::ops::{LiteralSkip, size_object_inner, size_object_with_prior};
use crate::{
    ARITY, BIN_REF, EMPTY_TUPLE, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, FUN, FunRef, HEAP_BITS,
    HeapAlloc, MAP, Node, RECORD, REF, SUB_BITS, Term, TermError, TermKind, size_object,
};
use std::collections::HashMap;
use std::sync::Arc;

enum Job {
    /// Copy a term into a slot; `true` disables sharing for this subgraph.
    Copy(Term, *mut u64, bool),
    FixBase(*mut u64),
}

/// Copy an Erlang term after sizing its entire reachable object graph.
/// Sharing of ordinary heap objects is deliberately not retained, as in erts.
pub fn copy_term<H: HeapAlloc + ?Sized>(root: Term, dst: &mut H) -> Result<Term, TermError> {
    // Port of erts/emulator/beam/copy.c:52 (`copy_object_x`): immediates are not sized.
    if root.is_immed() {
        return Ok(root);
    }
    validate_destination(root, dst)?;
    let size = size_object(root);
    copy_struct_x(root, size, dst, None)
}

/// `copy_struct` into `dst` using a size already returned by [`crate::size_object`] for `root`.
/// Port of erts/emulator/beam/copy.c:647 (`copy_struct_x`), OTP-29.1.1.
pub fn copy_struct<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    size: usize,
) -> Result<Term, TermError> {
    if root.is_immed() || size == 0 {
        return Ok(root);
    }
    validate_destination(root, dst)?;
    copy_struct_x(root, size, dst, None)
}

/// Whether `block` is a self-contained heap block that [`copy_shallow`] can copy word by word:
/// `root` is its first word, every pointer stays inside it (or is the empty tuple literal) and
/// it holds no off-heap thing (binary references, sub-bitstrings, external or magic things),
/// whose copy must link an owner into the destination.
// Port of the block contract of erts/emulator/beam/copy.c (copy_shallow_x), OTP-29.1.1: a term
// "guaranteed to be contained in a single heap block", here checked once when the block is made.
pub fn shallow_copyable(root: Term, block: &[u64]) -> bool {
    let base = block.as_ptr() as u64;
    if block.is_empty() || root.0 & 3 != 2 && root.0 & 3 != 1 || root.0 & !7 != base {
        return false;
    }
    let empty = crate::global_empty_tuple().0;
    let mut i = 0;
    while i < block.len() {
        let word = block[i];
        match word & 3 {
            3 => i += 1,
            1 | 2 => {
                let target = word & !7;
                if word != empty && !(target >= base && (target - base) < (block.len() as u64) * 8)
                {
                    return false;
                }
                i += 1;
            }
            _ => {
                let kind = word & 63;
                if kind == ARITY || kind == RECORD {
                    i += 1;
                    continue;
                }
                let plain_thing = matches!(
                    kind,
                    crate::POS_BIG | crate::NEG_BIG | crate::FLOAT | HEAP_BITS | MAP | FUN
                );
                let ordinary_ref = kind == REF
                    && block
                        .get(i + 1)
                        .is_some_and(|next| !crate::is_magic_ref_thing_with_hdr(word, *next));
                if !(plain_thing || ordinary_ref) {
                    return false;
                }
                i += copy_scan_skip(word);
            }
        }
    }
    i == block.len()
}

/// Copy the heap block `block` (see [`shallow_copyable`]) word by word into `dst`, offsetting
/// every pointer to its new location; returns the copy of `root`.
// Port of erts/emulator/beam/copy.c (copy_shallow_x, copy_shallow_obj_x), OTP-29.1.1, as used by
// erl_db_util.h (db_copy_object_from_ets).
pub fn copy_shallow<H: HeapAlloc + ?Sized>(
    root: Term,
    block: &[u64],
    dst: &mut H,
) -> Result<Term, TermError> {
    let base = dst.alloc(block.len()).ok_or(TermError::HeapFull)?;
    // SAFETY: `alloc` returned `block.len()` writable words that do not alias `block`, a live
    // table-owned block.
    let out = unsafe { std::slice::from_raw_parts_mut(base, block.len()) };
    let offset = (base as u64).wrapping_sub(block.as_ptr() as u64);
    let empty = crate::global_empty_tuple().0;
    let mut i = 0;
    while i < block.len() {
        let word = block[i];
        match word & 3 {
            1 | 2 if word != empty => {
                out[i] = word.wrapping_add(offset);
                i += 1;
            }
            0 => {
                let kind = word & 63;
                let skip = if kind == ARITY || kind == RECORD {
                    1
                } else {
                    copy_scan_skip(word)
                };
                out[i..i + skip].copy_from_slice(&block[i..i + skip]);
                i += skip;
            }
            _ => {
                out[i] = word;
                i += 1;
            }
        }
    }
    Ok(Term(root.0.wrapping_add(offset)))
}

/// Copy a nonempty tuple whose elements are all immediates in one pass, without sizing it first.
/// `None` for any other term, which the caller copies with [`copy_struct`]. The copy occupies
/// the tuple's arity plus one words.
// Port of erts/emulator/beam/copy.c (copy_struct_x, the const-tuple case: a tuple with only
// immediate elements needs no scan), OTP-29.1.1.
pub fn copy_flat_tuple<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
) -> Option<Result<Term, TermError>> {
    // SAFETY: the caller holds `root`'s heap live for this call, like every `Term` accessor.
    let tuple = unsafe { root.tuple_ref() }?;
    let elements = tuple.elements;
    if elements.is_empty() || elements.iter().any(|&word| word & 3 != 3) {
        return None;
    }
    let words = elements.len() + 1;
    let Some(base) = dst.alloc(words) else {
        return Some(Err(TermError::HeapFull));
    };
    // SAFETY: `alloc` returned `words` writable words that do not alias the source tuple.
    let out = unsafe { std::slice::from_raw_parts_mut(base, words) };
    out[0] = ((elements.len() as u64) << 6) | ARITY;
    out[1..].copy_from_slice(elements);
    Some(Ok(Term::from_ptr(base, 2)))
}

/// Copy a term, keeping references to literals outside the collector's purge area.
/// `literals` must be the snapshot used to size the destination.
/// Port of erts/emulator/beam/copy.c:647 (copy_struct_x with a litopt), OTP-29.1.1.
pub fn copy_term_litopt<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    literals: &LiteralAreas,
) -> Result<Term, TermError> {
    if root.is_immed() {
        return Ok(root);
    }
    validate_destination(root, dst)?;
    let size = crate::size_object_litopt(root, literals);
    copy_struct_x(root, size, dst, Some(literals))
}

/// `copy_struct` into `dst` using a size already returned by [`crate::size_object_litopt`]
/// for the same `literals` snapshot. Does not walk the term to size it again.
/// Port of erts/emulator/beam/copy.c:647 (`copy_struct_x`), OTP-29.1.1.
pub fn copy_struct_litopt<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    size: usize,
    literals: &LiteralAreas,
) -> Result<Term, TermError> {
    if root.is_immed() || size == 0 {
        return Ok(root);
    }
    validate_destination(root, dst)?;
    copy_struct_x(root, size, dst, Some(literals))
}

/// `erts_debug:copy_shared/2`: preserve sharing and keep literal references
/// unless `copy_literals` is set or they lie in the purge area.
/// Port of erts/emulator/beam/copy.c:1111 (copy_shared_calculate) and
/// copy.c:1382 (copy_shared_perform_x), OTP-29.1.1.
pub fn copy_shared<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    copy_literals: bool,
) -> Result<Term, TermError> {
    validate_destination(root, dst)?;
    let literals = LiteralAreas::current();
    let skip = if copy_literals {
        LiteralSkip::None
    } else {
        LiteralSkip::Kept(&literals)
    };
    let size = size_object_inner(root, true, Default::default(), skip, Some(&literals));
    copy_term_body(
        root,
        dst,
        true,
        size,
        &mut SharedCopyCache::default(),
        skip,
        Some(&literals),
    )
}

/// Copy a term while retaining aliases among its heap objects.
/// Port of erts/emulator/beam/copy.c:1111 (copy_shared_calculate), OTP-29.1.1.
pub fn copy_term_preserving_sharing<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
) -> Result<Term, TermError> {
    copy_term_preserving_sharing_with_cache(root, dst, &mut SharedCopyCache::default())
}

/// Cache aliases across roots copied in one literal-area collection.
#[derive(Default)]
pub struct SharedCopyCache {
    copied: HashMap<u64, Term>,
}

/// Copy one root while reusing aliases established by earlier roots.
/// Port of erts/emulator/beam/copy.c:1382 (copy_shared_perform_x), OTP-29.1.1.
pub fn copy_term_preserving_sharing_with_cache<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    cache: &mut SharedCopyCache,
) -> Result<Term, TermError> {
    validate_destination(root, dst)?;
    let size = size_object_with_prior(
        root,
        true,
        &mut Default::default(),
        Some(&cache.copied),
        LiteralSkip::None,
        None,
    );
    copy_term_body(root, dst, true, size, cache, LiteralSkip::None, None)
}

/// Cheney copy into one pre-sized heap block. Constant cons cells and leaf
/// objects grow down from the end; objects with children grow up from the start.
/// Port of erts/emulator/beam/copy.c:647 (`copy_struct_x`), OTP-29.1.1.
fn copy_struct_x<H: HeapAlloc + ?Sized>(
    root: Term,
    size: usize,
    dst: &mut H,
    litopt: Option<&LiteralAreas>,
) -> Result<Term, TermError> {
    if root.is_immed() || size == 0 {
        return Ok(root);
    }
    let base = dst.alloc(size).ok_or(TermError::HeapFull)?;
    copy_struct_into(root, base, size, dst, litopt)
}

enum CopyAt {
    Scan,
    List(*mut u64, Term),
    Boxed(*mut u64, Term),
}

fn copy_struct_into<H: HeapAlloc + ?Sized>(
    root: Term,
    base: *mut u64,
    size: usize,
    dst: &mut H,
    litopt: Option<&LiteralAreas>,
) -> Result<Term, TermError> {
    let hstart = base;
    let hsize = size * 8;
    let mut hp = base;
    let mut htop = base;
    // SAFETY: `base` addresses `size` reserved words; `hbot` is the end pointer.
    let mut hbot = unsafe { base.add(size) };
    let mut res = 0u64;
    let mut const_tuple: *mut u64 = std::ptr::null_mut();
    let mut at = match root.0 & 3 {
        1 => CopyAt::List(&mut res, root),
        2 => CopyAt::Boxed(&mut res, root),
        _ => return Ok(root),
    };
    // SAFETY: `base` is `size` writable words that do not alias `root`. Every
    // source pointer is a live cons or boxed object. Off-heap owners are
    // retained on `dst` the way copy_struct links them into `off_heap`.
    unsafe {
        loop {
            match at {
                CopyAt::Scan => {
                    if hp == htop {
                        debug_assert_eq!(htop, hbot, "copy_struct htop/hbot");
                        return Ok(Term(res));
                    }
                    let obj = Term(*hp);
                    match obj.0 & 3 {
                        3 => hp = hp.add(1),
                        1 => {
                            let objp = obj.raw_ptr();
                            if in_copy_area(objp, hstart, hsize) {
                                hp = hp.add(1);
                            } else {
                                let argp = hp;
                                hp = hp.add(1);
                                at = CopyAt::List(argp, obj);
                            }
                        }
                        2 => {
                            let objp = obj.raw_ptr();
                            if in_copy_area(objp, hstart, hsize) {
                                hp = hp.add(1);
                            } else {
                                let argp = hp;
                                hp = hp.add(1);
                                at = CopyAt::Boxed(argp, obj);
                            }
                        }
                        0 => {
                            let hdr = obj.0;
                            if header_is_thing(hdr) || hp == const_tuple {
                                hp = hp.add(copy_scan_skip(hdr));
                            } else {
                                hp = hp.add(1);
                            }
                        }
                        _ => hp = hp.add(1),
                    }
                }
                CopyAt::List(mut argp, mut obj) => {
                    let mut objp = obj.raw_ptr();
                    if lit_kept(litopt, objp) {
                        *argp = obj.0;
                        at = CopyAt::Scan;
                        continue;
                    }
                    loop {
                        let tp = argp;
                        let elem = Term(*objp);
                        let tailp = if elem.is_immed() {
                            hbot = hbot.sub(2);
                            *hbot = elem.0;
                            hbot.add(1)
                        } else {
                            *htop = elem.0;
                            let tailp = htop.add(1);
                            htop = htop.add(2);
                            tailp
                        };
                        *tp = Term::from_ptr(tailp.sub(1), 1).0;
                        obj = Term(*objp.add(1));
                        if obj.0 & 3 != 1 {
                            argp = tailp;
                            break;
                        }
                        objp = obj.raw_ptr();
                        if lit_kept(litopt, objp) {
                            *tailp = obj.0;
                            at = CopyAt::Scan;
                            break;
                        }
                        argp = tailp;
                    }
                    if matches!(at, CopyAt::Scan) {
                        continue;
                    }
                    match obj.0 & 3 {
                        3 => {
                            *argp = obj.0;
                            at = CopyAt::Scan;
                        }
                        2 => at = CopyAt::Boxed(argp, obj),
                        _ => {
                            debug_assert!(false, "copy_struct bad list tail {:#x}", obj.0);
                            *argp = obj.0;
                            at = CopyAt::Scan;
                        }
                    }
                }
                CopyAt::Boxed(argp, obj) => {
                    let mut objp = obj.raw_ptr();
                    if lit_kept(litopt, objp) {
                        *argp = obj.0;
                        at = CopyAt::Scan;
                        continue;
                    }
                    let hdr = *objp;
                    match hdr & 63 {
                        ARITY => {
                            let n = (hdr >> 6) as usize;
                            if n == 0 {
                                *argp = (std::ptr::from_ref(&EMPTY_TUPLE) as u64) | 2;
                                at = CopyAt::Scan;
                                continue;
                            }
                            *argp = Term::from_ptr(htop, 2).0;
                            let tp = htop;
                            *htop = *objp;
                            htop = htop.add(1);
                            objp = objp.add(1);
                            let mut const_flag = true;
                            for _ in 0..n {
                                let elem = Term(*objp);
                                objp = objp.add(1);
                                if !elem.is_immed() {
                                    const_flag = false;
                                }
                                *htop = elem.0;
                                htop = htop.add(1);
                            }
                            if const_flag {
                                const_tuple = tp;
                            }
                        }
                        RECORD => {
                            let n = (hdr >> 6) as usize;
                            *argp = Term::from_ptr(htop, 2).0;
                            let words = n + 1;
                            std::ptr::copy_nonoverlapping(objp, htop, words);
                            htop = htop.add(words);
                        }
                        SUB_BITS => {
                            copy_sub_bits(obj, objp, argp, &mut hbot, dst)?;
                        }
                        FUN => {
                            let nfree = ((hdr >> 16) & 255) as usize;
                            let words = 2 + nfree;
                            let dst_fun = htop;
                            std::ptr::copy_nonoverlapping(objp, dst_fun, words);
                            htop = htop.add(words);
                            *argp = Term::from_ptr(dst_fun, 2).0;
                        }
                        EXTERNAL_PID | EXTERNAL_PORT | EXTERNAL_REF => {
                            copy_off_heap_thing(objp, hdr, argp, &mut htop, dst, false)?;
                        }
                        MAP => {
                            copy_map(objp, hdr, argp, &mut htop);
                        }
                        REF if crate::is_magic_ref_thing_with_hdr(hdr, *objp.add(1)) => {
                            let owner = crate::MagicRef::thing_owner(*objp.add(1), true);
                            let thing = htop;
                            copy_off_heap_thing(objp, hdr, argp, &mut htop, dst, true)?;
                            dst.link_magic_ref(thing, owner)?;
                        }
                        _ => {
                            let words = ((hdr >> 6) as usize) + 1;
                            hbot = hbot.sub(words);
                            std::ptr::copy_nonoverlapping(objp, hbot, words);
                            *argp = Term::from_ptr(hbot, 2).0;
                        }
                    }
                    at = CopyAt::Scan;
                }
            }
        }
    }
}

fn copy_map(objp: *const u64, hdr: u64, argp: *mut u64, htop: &mut *mut u64) {
    // Port of copy.c:910-932. Flatmap words are header, size, keys, values.
    // HAMT heads copy the header then fall through to the node payload.
    let tp = *htop;
    let map_type = (hdr >> 6) & 3;
    // SAFETY: the source map is live and `size_object_x` reserved these words.
    unsafe {
        match map_type {
            0 => {
                let words = (*objp.add(1) as usize) + 3;
                *argp = Term::from_ptr(tp, 2).0;
                std::ptr::copy_nonoverlapping(objp, tp, words);
                *htop = tp.add(words);
            }
            2 | 3 => {
                *tp = *objp;
                let n = 1 + ((hdr >> 16) as u16).count_ones() as usize;
                std::ptr::copy_nonoverlapping(objp.add(1), tp.add(1), n);
                *htop = tp.add(1 + n);
                *argp = Term::from_ptr(tp, 2).0;
            }
            1 => {
                let n = 1 + ((hdr >> 16) as u16).count_ones() as usize;
                std::ptr::copy_nonoverlapping(objp, tp, n);
                *htop = tp.add(n);
                *argp = Term::from_ptr(tp, 2).0;
            }
            _ => debug_assert!(false, "copy_struct bad hashmap type {map_type}"),
        }
    }
}

fn copy_off_heap_thing<H: HeapAlloc + ?Sized>(
    objp: *const u64,
    hdr: u64,
    argp: *mut u64,
    htop: &mut *mut u64,
    dst: &mut H,
    magic_already_retained: bool,
) -> Result<(), TermError> {
    // Port of copy.c:882-908 (`L_off_heap_node_container_common`).
    let words = ((hdr >> 6) as usize) + 1;
    let tp = *htop;
    // SAFETY: the external or magic thing is live and the destination has `words` free.
    unsafe {
        std::ptr::copy_nonoverlapping(objp, tp, words);
        *argp = Term::from_ptr(tp, 2).0;
        *htop = tp.add(words);
        if !magic_already_retained {
            let ptr = *tp.add(1) as *const Node;
            Arc::increment_strong_count(ptr);
            // The copied `next` belongs to the source list; the link below rewrites it.
            *tp.add(2) = 0;
            dst.link_node(tp, Arc::from_raw(ptr));
        }
    }
    Ok(())
}

fn copy_sub_bits<H: HeapAlloc + ?Sized>(
    obj: Term,
    objp: *const u64,
    argp: *mut u64,
    hbot: &mut *mut u64,
    dst: &mut H,
) -> Result<(), TermError> {
    // Port of copy.c:812-864. A BinRef is copied with its sub-bits; a match
    // context over a heap bitstring becomes a heap bitstring of that window.
    // SAFETY: `obj` is a live sub-bits. Word 4 is its original boxed term. The
    // destination tail has the words `size_object_x` reserved for this object,
    // and those words do not overlap the source.
    unsafe {
        let orig = Term(*objp.add(4));
        let underlying = orig.raw_ptr();
        let uhdr = *underlying;
        if uhdr & 63 == BIN_REF {
            crate::bits::writable_finalize(obj);
            let to_br = (*hbot).sub(3);
            *hbot = to_br;
            let to_sb = (*hbot).sub(5);
            *hbot = to_sb;
            std::ptr::copy_nonoverlapping(underlying, to_br, 3);
            std::ptr::copy_nonoverlapping(objp, to_sb, 5);
            *to_sb.add(4) = Term::from_ptr(to_br, 2).0;
            *argp = Term::from_ptr(to_sb, 2).0;
            let (ptr, flags, overhead, owner) =
                crate::bits::clone_binary_owner(Term::from_ptr(underlying.cast_mut(), 2))?;
            crate::bits::retain_cloned_binary_owner(dst, to_br, ptr, flags, overhead, owner)?;
            return Ok(());
        }
        let start = *objp.add(2) as usize;
        let end = *objp.add(3) as usize;
        let bits = end.wrapping_sub(start);
        let words = heap_bits_words(bits);
        let to = (*hbot).sub(words);
        *hbot = to;
        *to = (((words - 1) as u64) << 6) | HEAP_BITS;
        *to.add(1) = bits as u64;
        if words > 2 {
            let payload = (words - 2) * 8;
            std::ptr::write_bytes(to.add(2).cast::<u8>(), 0, payload);
            let base = (*objp.add(1) & !3) as *const u8;
            let src_len = start.saturating_add(bits).div_ceil(8);
            // The source window is the bitstring `size_object_x` measured, and
            // `payload` is the zeroed heap-bitstring reserved for it.
            let src = std::slice::from_raw_parts(base, src_len);
            let dst = std::slice::from_raw_parts_mut(to.add(2).cast::<u8>(), payload);
            copy_binary_to_buffer(dst, src, start, bits);
        }
        *argp = Term::from_ptr(to, 2).0;
    }
    Ok(())
}

#[inline(always)]
pub(crate) fn copy_binary_to_buffer(dst: &mut [u8], src: &[u8], src_offset: usize, size: usize) {
    // Port of erts/emulator/beam/erl_bits.h:541 (`copy_binary_to_buffer`), OTP-29.1.1.
    // `src` / `dst` are the live windows the caller already bounded.
    if size == 0 {
        return;
    }
    if src_offset.is_multiple_of(8) && size.is_multiple_of(8) {
        let start = src_offset / 8;
        let nbytes = size / 8;
        dst[..nbytes].copy_from_slice(&src[start..start + nbytes]);
        return;
    }
    for i in 0..size {
        let src_bit = src_offset + i;
        let byte = src[src_bit / 8];
        let bit = (byte >> (7 - src_bit % 8)) & 1;
        dst[i / 8] |= bit << (7 - i % 8);
    }
}

#[inline]
fn lit_kept(litopt: Option<&LiteralAreas>, ptr: *const u64) -> bool {
    litopt.is_some_and(|areas| areas.keeps(ptr as u64))
}

#[inline]
fn in_copy_area(ptr: *const u64, start: *mut u64, nbytes: usize) -> bool {
    // Port of erl_alloc.h `ErtsInArea` as used by copy.c:712.
    (ptr as usize).wrapping_sub(start as usize) < nbytes
}

#[inline]
fn header_is_thing(hdr: u64) -> bool {
    // Port of erl_term.h:170-175. Tuples and records are transparent.
    !((hdr & 0x3b) == 0 || (hdr & 0x3f) == RECORD)
}

#[inline]
fn copy_scan_skip(hdr: u64) -> usize {
    // Port of erl_term.h:310 (`header_arity`) and copy.c:951-956, OTP-29.1.1.
    // Flatmaps store MAP_HEADER_FLATMAP, so the arity field is 1 and this skip
    // covers the header plus the raw size word. HAMT nodes store arity 0.
    let sub = hdr & 63;
    let arity = if sub == MAP {
        ((hdr >> 8) & 0xff) as usize
    } else if sub == FUN {
        1
    } else {
        (hdr >> 6) as usize
    };
    arity + 1
}

#[inline]
fn heap_bits_words(num_bits: usize) -> usize {
    let nbytes = num_bits.div_ceil(8);
    2 + nbytes.div_ceil(8)
}

fn validate_destination<H: HeapAlloc + ?Sized>(root: Term, dst: &H) -> Result<(), TermError> {
    if dst.supports_writable_binary() {
        return Ok(());
    }
    let mut stack: smallvec::SmallVec<[Term; 32]> = smallvec::SmallVec::new();
    stack.push(root);
    while let Some(term) = stack.pop() {
        if crate::bits::binary_owner_is_writable(term) {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        stack.extend(crate::ops::children(term).filter(|child| child.is_pointer()));
    }
    Ok(())
}

fn copy_term_body<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    preserve_sharing: bool,
    size: usize,
    cache: &mut SharedCopyCache,
    skip: LiteralSkip<'_>,
    unshared_literals: Option<&LiteralAreas>,
) -> Result<Term, TermError> {
    if size == 0 {
        return Ok(cache
            .copied
            .get(&(root.bits() & !7))
            .copied()
            .unwrap_or(root));
    }
    let base = dst.alloc(size).ok_or(TermError::HeapFull)?;
    let mut offset = 0;
    let mut root_word = 0_u64;
    let mut jobs: smallvec::SmallVec<[Job; 32]> = smallvec::SmallVec::new();
    jobs.push(Job::Copy(root, &mut root_word, false));
    while let Some(job) = jobs.pop() {
        match job {
            Job::FixBase(p) => {
                // SAFETY: The original pointer in this copied SubBits has been rewritten.
                unsafe {
                    let original = Term(*p.add(4));
                    let flags = *p.add(1) & 3;
                    if let Some(h) = original.header() {
                        if h & 63 == HEAP_BITS {
                            *p.add(1) = (original.raw_ptr().add(2) as u64) | flags;
                        } else if h & 63 == SUB_BITS {
                            *p.add(1) = (*original.raw_ptr().add(1) & !3) | flags;
                        }
                    }
                }
            }
            Job::Copy(source, slot, unshared) => {
                if source.bits() == ((&EMPTY_TUPLE as *const u64 as u64) | 2) {
                    // SAFETY: OTP's canonical empty tuple is static, not heap-owned.
                    unsafe { *slot = source.bits() };
                    continue;
                }
                // Port of erts/emulator/beam/copy.c:1164-1170 and copy.c:1450-1460
                // (copy_shared_*): literals that must be copied are copied with
                // copy_struct, i.e. without sharing, once per occurrence.
                let unshared = unshared
                    || (preserve_sharing
                        && !skip.skips(source.bits() & !7)
                        && unshared_literals.is_some_and(|l| l.is_literal(source.bits() & !7)));
                let sharing = preserve_sharing && !unshared;
                let shared_copy = if sharing {
                    cache.copied.get(&(source.bits() & !7)).copied()
                } else {
                    None
                };
                // Port of erts/emulator/beam/copy.c:720,744 (literals are
                // left in place by copy_struct_x with a litopt), OTP-29.1.1.
                if !source.is_pointer() || shared_copy.is_some() || skip.skips(source.bits() & !7) {
                    // SAFETY: slot belongs to the destination allocation.
                    unsafe {
                        *slot = shared_copy.unwrap_or(source).bits();
                    }
                    continue;
                }
                let source_address = source.bits() & !7;
                let is_list = source.classify() == TermKind::List;
                if is_list {
                    // A cons run is laid out in one reserved span. Only boxed heads
                    // need deferred work; ordinary integer lists use no host jobs.
                    // SAFETY: source is a live cons pointer.
                    let mut from = unsafe { source.raw_ptr() };
                    let mut link = slot;
                    loop {
                        // SAFETY: each source cell is live and size_object reserved two
                        // words for every occurrence in the run.
                        let (head, tail) = unsafe { (Term(*from), Term(*from.add(1))) };
                        // SAFETY: offset remains inside the single destination reservation.
                        let to = unsafe { base.add(offset) };
                        offset += 2;
                        // SAFETY: to points at two writable destination words; link
                        // points at either the root slot or the preceding tail word.
                        unsafe {
                            *link = Term::from_ptr(to, 1).bits();
                            *to = head.bits();
                        }
                        if sharing {
                            cache
                                .copied
                                .insert(from as usize as u64, Term::from_ptr(to, 1));
                        }
                        if head.is_pointer() {
                            jobs.push(Job::Copy(head, to, unshared));
                        }
                        // SAFETY: the tail word belongs to this initialized cell.
                        link = unsafe { to.add(1) };
                        if tail.bits() & 3 == 1 && skip.skips(tail.bits() & !7) {
                            // SAFETY: link is the last destination cons tail word.
                            unsafe { *link = tail.bits() };
                            break;
                        }
                        if tail.bits() == (from as u64).wrapping_sub(16) | 1 {
                            // SAFETY: the tail tag proves the predecessor is live.
                            from = unsafe { from.sub(2) };
                            continue;
                        }
                        if tail.bits() & 3 == 1 {
                            if sharing {
                                jobs.push(Job::Copy(tail, link, unshared));
                                break;
                            }
                            // SAFETY: a tagged cons pointer belongs to the live source.
                            from = unsafe { tail.raw_ptr() };
                            continue;
                        }
                        if tail.is_pointer() {
                            jobs.push(Job::Copy(tail, link, unshared));
                        } else {
                            // SAFETY: link is the last destination cons tail word.
                            unsafe { *link = tail.bits() };
                        }
                        break;
                    }
                    continue;
                }
                crate::bits::writable_finalize(source);
                let header = source.header().unwrap_or(0);
                // SAFETY: source is live and its header describes the allocation.
                let words = unsafe { crate::boxed_object_words(header, source.raw_ptr()) };
                // SAFETY: source is live and size_object reserved enough destination words.
                let (from, to) = unsafe { (source.raw_ptr(), base.add(offset)) };
                offset += words;
                // SAFETY: allocated ranges are disjoint and each has words initialized.
                unsafe {
                    std::ptr::copy_nonoverlapping(from, to, words);
                    *slot = Term::from_ptr(to, 2).bits();
                }
                if sharing {
                    cache.copied.insert(source_address, Term::from_ptr(to, 2));
                }
                match header & 63 {
                    ARITY => {
                        for i in (1..words).rev() {
                            // SAFETY: tuple elements occupy words 1..words.
                            unsafe {
                                jobs.push(Job::Copy(Term(*to.add(i)), to.add(i), unshared));
                            }
                        }
                    }
                    MAP => {
                        for i in crate::hamt::child_range(header, words).rev() {
                            // SAFETY: the map header determines its term-bearing slots.
                            unsafe {
                                jobs.push(Job::Copy(Term(*to.add(i)), to.add(i), unshared));
                            }
                        }
                    }
                    RECORD => {
                        for i in (1..words).rev() {
                            // SAFETY: record definition and values are terms.
                            unsafe {
                                jobs.push(Job::Copy(Term(*to.add(i)), to.add(i), unshared));
                            }
                        }
                    }
                    SUB_BITS => {
                        // SAFETY: offset four holds the original binary term.
                        unsafe {
                            jobs.push(Job::FixBase(to));
                            jobs.push(Job::Copy(Term(*to.add(4)), to.add(4), unshared));
                        }
                    }
                    FUN => {
                        // SAFETY: source fun entries are permanent code-table entries.
                        match unsafe { source.fun_ref().unwrap() } {
                            FunRef::Local { .. } => {
                                for i in (2..words).rev() {
                                    // SAFETY: local fun environment starts at word two.
                                    unsafe {
                                        jobs.push(Job::Copy(Term(*to.add(i)), to.add(i), unshared));
                                    }
                                }
                            }
                            FunRef::Export { .. } => {}
                        }
                    }
                    EXTERNAL_PID | EXTERNAL_PORT | EXTERNAL_REF => {
                        // SAFETY: external identity word one stores a retained Arc<Node> pointer.
                        unsafe {
                            let ptr = *to.add(1) as *const Node;
                            Arc::increment_strong_count(ptr);
                            *to.add(2) = 0;
                            dst.link_node(to, Arc::from_raw(ptr));
                        }
                    }
                    BIN_REF => {
                        // SAFETY: a BinRef stores an Arc pointer selected by word two.
                        unsafe {
                            let (ptr, flags, overhead, owner) =
                                crate::bits::clone_binary_owner(source)?;
                            crate::bits::retain_cloned_binary_owner(
                                dst, to, ptr, flags, overhead, owner,
                            )?;
                        }
                    }
                    // Port of erts/emulator/beam/copy.c:934-939 (copy_struct, magic ref), OTP-29.1.1.
                    REF if crate::is_magic_ref_thing_with_hdr(
                        header,
                        crate::heap::load(to.wrapping_add(1)),
                    ) =>
                    {
                        let owner = crate::MagicRef::thing_owner(
                            crate::heap::load(to.wrapping_add(1)),
                            true,
                        );
                        dst.link_magic_ref(to, owner)?;
                    }
                    _ => {}
                }
            }
        }
    }
    debug_assert_eq!(offset, size);
    Ok(Term(root_word))
}

#[cfg(test)]
mod shallow_tests {
    use super::*;
    use crate::VecHeap;

    fn block_root(block: &[u64]) -> Term {
        Term::from_ptr(block.as_ptr().cast_mut(), 2)
    }

    #[test]
    fn rejects_blocks_that_are_not_self_contained() {
        // A tuple whose element points outside the block.
        let outside = 0x1000_0000_u64 | 2;
        let block = [1 << 6, outside];
        assert!(!shallow_copyable(block_root(&block), &block));
        // A tuple of one immediate is a block.
        let block = [1 << 6, Term::small(5).unwrap().0];
        assert!(shallow_copyable(block_root(&block), &block));
        // A thing cut off by the end of the block (float header, no payload).
        let block = [(1 << 6) | crate::FLOAT];
        assert!(!shallow_copyable(block_root(&block), &block));
        // A root that is not the first word.
        let block = [1 << 6, Term::small(5).unwrap().0];
        assert!(!shallow_copyable(
            Term::from_ptr(block.as_ptr().wrapping_add(1).cast_mut(), 2),
            &block
        ));
    }

    #[test]
    fn rejects_off_heap_things() {
        // A magic reference thing needs an owner link in the destination.
        let block = [crate::REF_THING_HEADER, 0, 0];
        assert!(!shallow_copyable(block_root(&block), &block));
        // A BinRef likewise.
        let block = [(2 << 6) | BIN_REF, 0, 0];
        assert!(!shallow_copyable(block_root(&block), &block));
    }

    #[test]
    fn copies_internal_pointers_to_the_new_block() {
        // {1, [2]} laid out as tuple (3 words) followed by one cons cell.
        let mut block = [0_u64; 5];
        let cell = block.as_ptr().wrapping_add(3).cast_mut();
        block[0] = 2 << 6;
        block[1] = Term::small(1).unwrap().0;
        block[2] = Term::from_ptr(cell, 1).0;
        block[3] = Term::small(2).unwrap().0;
        block[4] = Term::NIL.0;
        let root = block_root(&block);
        assert!(shallow_copyable(root, &block));
        let mut dst = VecHeap::new();
        let copy = copy_shallow(root, &block, &mut dst).unwrap();
        assert_ne!(copy.0, root.0);
        assert_eq!(
            crate::to_owned(copy).unwrap(),
            crate::to_owned(root).unwrap()
        );
    }
}

#[cfg(test)]
mod flat_tuple_tests {
    use super::*;
    use crate::{TermBuilder, VecHeap};

    #[test]
    fn copies_tuples_of_immediates_only() {
        let mut source = VecHeap::new();
        let flat = TermBuilder::new(&mut source)
            .tuple(&[Term::small(1).unwrap(), Term::NIL])
            .unwrap();
        let mut dst = VecHeap::new();
        let copy = copy_flat_tuple(flat, &mut dst)
            .expect("a flat tuple")
            .unwrap();
        assert_ne!(copy.0, flat.0);
        assert_eq!(
            crate::to_owned(copy).unwrap(),
            crate::to_owned(flat).unwrap()
        );
        let inner = TermBuilder::new(&mut source)
            .tuple(&[Term::small(2).unwrap()])
            .unwrap();
        let nested = TermBuilder::new(&mut source)
            .tuple(&[Term::small(1).unwrap(), inner])
            .unwrap();
        assert!(copy_flat_tuple(nested, &mut dst).is_none());
        let empty = TermBuilder::new(&mut source).tuple(&[]).unwrap();
        assert!(copy_flat_tuple(empty, &mut dst).is_none());
        assert!(copy_flat_tuple(Term::small(1).unwrap(), &mut dst).is_none());
    }
}
