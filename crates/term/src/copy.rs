//! Iterative deep copy into one destination allocation.
use crate::fun::{clone_export_entry, clone_fun_entry};
use crate::{
    ARITY, BIN_REF, EMPTY_TUPLE, EXTERNAL_PID, EXTERNAL_PORT, EXTERNAL_REF, ExportEntry, FUN,
    FunEntry, FunRef, HEAP_BITS, HeapAlloc, MAGIC_REF, MAP, Node, RECORD, SUB_BITS, Term,
    TermError, TermKind, size_object,
};
use std::sync::Arc;

enum Job {
    Copy(Term, *mut u64),
    FixBase(*mut u64),
}

/// Copy an Erlang term after sizing its entire reachable object graph.
/// Sharing of ordinary heap objects is deliberately not retained, as in erts.
pub fn copy_term<H: HeapAlloc>(root: Term, dst: &mut H) -> Result<Term, TermError> {
    if !dst.supports_writable_binary() {
        let mut stack = vec![root];
        while let Some(term) = stack.pop() {
            if crate::bits::binary_owner_is_writable(term) {
                return Err(TermError::Unsupported("writable binary heap owner"));
            }
            stack.extend(crate::ops::children(term).filter(|child| child.is_pointer()));
        }
    }
    let size = size_object(root);
    if size == 0 {
        return Ok(root);
    }
    let base = dst.alloc(size).ok_or(TermError::HeapFull)?;
    let mut offset = 0;
    let mut root_word = 0_u64;
    let mut jobs = vec![Job::Copy(root, &mut root_word)];
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
            Job::Copy(source, slot) => {
                if source.bits() == ((&EMPTY_TUPLE as *const u64 as u64) | 2) {
                    // SAFETY: OTP's canonical empty tuple is static, not heap-owned.
                    unsafe { *slot = source.bits() };
                    continue;
                }
                if !source.is_pointer() {
                    // SAFETY: slot belongs to the destination allocation.
                    unsafe {
                        *slot = source.bits();
                    }
                    continue;
                }
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
                        if head.is_pointer() {
                            jobs.push(Job::Copy(head, to));
                        }
                        // SAFETY: the tail word belongs to this initialized cell.
                        link = unsafe { to.add(1) };
                        if tail.bits() == (from as u64).wrapping_sub(16) | 1 {
                            // SAFETY: the tail tag proves the predecessor is live.
                            from = unsafe { from.sub(2) };
                            continue;
                        }
                        if tail.bits() & 3 == 1 {
                            // SAFETY: a tagged cons pointer belongs to the live source.
                            from = unsafe { tail.raw_ptr() };
                            continue;
                        }
                        if tail.is_pointer() {
                            jobs.push(Job::Copy(tail, link));
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
                match header & 63 {
                    ARITY => {
                        for i in (1..words).rev() {
                            // SAFETY: tuple elements occupy words 1..words.
                            unsafe {
                                jobs.push(Job::Copy(Term(*to.add(i)), to.add(i)));
                            }
                        }
                    }
                    MAP => {
                        for i in crate::hamt::child_range(header, words).rev() {
                            // SAFETY: the map header determines its term-bearing slots.
                            unsafe {
                                jobs.push(Job::Copy(Term(*to.add(i)), to.add(i)));
                            }
                        }
                    }
                    RECORD => {
                        for i in (1..words).rev() {
                            // SAFETY: record definition and values are terms.
                            unsafe {
                                jobs.push(Job::Copy(Term(*to.add(i)), to.add(i)));
                            }
                        }
                    }
                    SUB_BITS => {
                        // SAFETY: offset four holds the original binary term.
                        unsafe {
                            jobs.push(Job::FixBase(to));
                            jobs.push(Job::Copy(Term(*to.add(4)), to.add(4)));
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
                                        jobs.push(Job::Copy(Term(*to.add(i)), to.add(i)));
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
