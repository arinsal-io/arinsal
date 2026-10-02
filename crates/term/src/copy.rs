//! Iterative deep copy into one destination allocation.
use crate::fun::{clone_export_entry, clone_fun_entry};
use crate::literal::LiteralAreas;
use crate::ops::{LiteralSkip, size_object_inner};
use crate::{
    ARITY, BIN_REF, EMPTY_TUPLE, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, ExportEntry, FUN,
    FunEntry, FunRef, HEAP_BITS, HeapAlloc, MAGIC_REF, MAP, Node, RECORD, SUB_BITS, Term,
    TermError, TermKind, size_object,
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
    validate_destination(root, dst)?;
    copy_term_with_mode(root, dst, false, size_object(root), LiteralSkip::None)
}

/// Copy a term, keeping references to literals outside the collector's purge area.
/// `literals` must be the snapshot used to size the destination.
/// Port of erts/emulator/beam/copy.c:648 (copy_struct_x with a litopt), OTP-29.1.1.
pub fn copy_term_litopt<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    literals: &LiteralAreas,
) -> Result<Term, TermError> {
    validate_destination(root, dst)?;
    let skip = LiteralSkip::Kept(literals);
    let size = size_object_inner(root, false, Default::default(), skip, None);
    copy_term_with_mode(root, dst, false, size, skip)
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
    let size = crate::size_object_preserving_sharing_after(root, cache.copied.keys().copied());
    copy_term_body(root, dst, true, size, cache, LiteralSkip::None, None)
}

fn validate_destination<H: HeapAlloc + ?Sized>(root: Term, dst: &H) -> Result<(), TermError> {
    if dst.supports_writable_binary() {
        return Ok(());
    }
    let mut stack = vec![root];
    while let Some(term) = stack.pop() {
        if crate::bits::binary_owner_is_writable(term) {
            return Err(TermError::Unsupported("writable binary heap owner"));
        }
        stack.extend(crate::ops::children(term).filter(|child| child.is_pointer()));
    }
    Ok(())
}

fn copy_term_with_mode<H: HeapAlloc + ?Sized>(
    root: Term,
    dst: &mut H,
    preserve_sharing: bool,
    size: usize,
    skip: LiteralSkip<'_>,
) -> Result<Term, TermError> {
    copy_term_body(
        root,
        dst,
        preserve_sharing,
        size,
        &mut SharedCopyCache::default(),
        skip,
        None,
    )
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
    let mut jobs = vec![Job::Copy(root, &mut root_word, false)];
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
                        // SAFETY: source fun entry is retained by the source heap.
                        match unsafe { source.fun_ref().unwrap() } {
                            FunRef::Local { .. } => {
                                // SAFETY: word one holds Arc<FunEntry> data.
                                unsafe {
                                    dst.retain_fun(clone_fun_entry(*to.add(1) as *const FunEntry));
                                }
                                for i in (2..words).rev() {
                                    // SAFETY: local fun environment starts at word two.
                                    unsafe {
                                        jobs.push(Job::Copy(Term(*to.add(i)), to.add(i), unshared));
                                    }
                                }
                            }
                            FunRef::Export { .. } => {
                                // SAFETY: word one holds Arc<ExportEntry> data.
                                unsafe {
                                    dst.retain_export(clone_export_entry(
                                        *to.add(1) as *const ExportEntry
                                    ));
                                }
                            }
                        }
                    }
                    EXTERNAL_PID | EXTERNAL_PORT | EXTERNAL_REF => {
                        // SAFETY: external identity word one stores a retained Arc<Node> pointer.
                        unsafe {
                            let ptr = *to.add(1) as *const Node;
                            Arc::increment_strong_count(ptr);
                            dst.retain_node(Arc::from_raw(ptr));
                        }
                    }
                    BIN_REF => {
                        // SAFETY: a BinRef stores an Arc pointer selected by word two.
                        unsafe {
                            let (ptr, flags) = crate::bits::clone_binary_owner(source);
                            crate::bits::retain_cloned_binary_owner(dst, ptr, flags)?;
                        }
                    }
                    MAGIC_REF => {
                        // SAFETY: source heap retains this Arc while the copy is in progress.
                        unsafe {
                            let ptr = *to.add(1) as *const crate::MagicRef;
                            Arc::increment_strong_count(ptr);
                            dst.retain_magic(Arc::from_raw(ptr));
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    debug_assert_eq!(offset, size);
    Ok(Term(root_word))
}
