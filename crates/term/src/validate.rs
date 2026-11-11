//! Debug checks that boxed and list pointers stay inside live allocations.
//!
//! Release builds omit every call unless the `validate-terms` feature is on.
//! Debug builds consult `ARINSAL_VALIDATE=1` once and otherwise return
//! immediately. Callers publish a phase label through [`set_context`]
//! before they read a term.

use crate::{ProcessHeap, Term};
use std::cell::RefCell;
use std::sync::{Mutex, OnceLock};

struct Range {
    start: usize,
    end: usize,
}

static STABLE: Mutex<Vec<Range>> = Mutex::new(Vec::new());

thread_local! {
    static CONTEXT: RefCell<String> = const { RefCell::new(String::new()) };
}

/// Whether heap reads should check pointer terms.
#[inline(always)]
pub fn active() -> bool {
    #[cfg(feature = "validate-terms")]
    {
        true
    }
    #[cfg(all(debug_assertions, not(feature = "validate-terms")))]
    {
        debug_flag()
    }
    #[cfg(not(any(feature = "validate-terms", debug_assertions)))]
    {
        false
    }
}

#[cfg(all(debug_assertions, not(feature = "validate-terms")))]
fn debug_flag() -> bool {
    use std::sync::atomic::{AtomicU8, Ordering};
    static FLAG: AtomicU8 = AtomicU8::new(0);
    match FLAG.load(Ordering::Relaxed) {
        1 => true,
        2 => false,
        _ => {
            let enabled = std::env::var_os("ARINSAL_VALIDATE").is_some_and(|value| value == "1");
            FLAG.store(if enabled { 1 } else { 2 }, Ordering::Relaxed);
            enabled
        }
    }
}

#[cfg(debug_assertions)]
fn tracking() -> bool {
    cfg!(test) || active() || gc_verify_active()
}

#[cfg(debug_assertions)]
fn gc_verify_active() -> bool {
    static VERIFY: OnceLock<bool> = OnceLock::new();
    *VERIFY.get_or_init(|| {
        std::env::var_os("ARINSAL_GC_VERIFY").as_deref() == Some(std::ffi::OsStr::new("1"))
    })
}

#[cfg(not(debug_assertions))]
fn tracking() -> bool {
    cfg!(test) || active()
}

/// Remember `M:F/A opcode` for the next failing check on this thread.
pub fn set_context(context: &str) {
    CONTEXT.with(|slot| {
        let mut text = slot.borrow_mut();
        text.clear();
        text.push_str(context);
    });
}

fn context_label(suffix: &str) -> String {
    CONTEXT.with(|slot| {
        let text = slot.borrow();
        if text.is_empty() {
            if suffix.is_empty() {
                "unknown".to_owned()
            } else {
                suffix.to_owned()
            }
        } else if suffix.is_empty() {
            text.clone()
        } else {
            format!("{text} {suffix}")
        }
    })
}

/// Record a live `VecHeap` chunk. Literal areas, persistent terms, and the
/// process dictionary are all `VecHeap`s; module literals are private, so the
/// checker recognizes them by this table instead of a back-pointer.
#[cfg(any(feature = "validate-terms", debug_assertions, test))]
pub(crate) fn note_stable_range(start: usize, bytes: usize) {
    if !tracking() || bytes == 0 {
        return;
    }
    let mut ranges = STABLE.lock().unwrap_or_else(|error| error.into_inner());
    ranges.push(Range {
        start,
        end: start.saturating_add(bytes),
    });
}

/// Drop a chunk previously passed to [`note_stable_range`].
#[cfg(any(feature = "validate-terms", debug_assertions, test))]
pub(crate) fn forget_stable_range(start: usize) {
    if !tracking() {
        return;
    }
    let mut ranges = STABLE.lock().unwrap_or_else(|error| error.into_inner());
    ranges.retain(|range| range.start != start);
}

fn stable_contains(addr: usize) -> bool {
    if !tracking() {
        return false;
    }
    let ranges = STABLE.lock().unwrap_or_else(|error| error.into_inner());
    ranges
        .iter()
        .any(|range| addr >= range.start && addr < range.end)
}

fn stable_count() -> usize {
    if !tracking() {
        return 0;
    }
    STABLE
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .len()
}

fn in_span(start: usize, bytes: usize, addr: usize) -> bool {
    bytes > 0 && addr >= start && addr < start.saturating_add(bytes)
}

fn heap_contains(heap: &ProcessHeap, addr: usize) -> bool {
    let young = heap.words.len() * 8;
    if in_span(heap.words.as_ptr() as usize, young, addr) {
        return true;
    }
    let old = heap.old_words.len() * 8;
    if in_span(heap.old_words.as_ptr() as usize, old, addr) {
        return true;
    }
    heap.fragments.iter().enumerate().any(|(index, fragment)| {
        in_span(
            fragment.as_ptr() as usize,
            heap.fragment_used_words(index, fragment) * 8,
            addr,
        )
    })
}

fn is_static_empty_tuple(addr: usize) -> bool {
    if addr == std::ptr::from_ref(&crate::EMPTY_TUPLE) as usize {
        return true;
    }
    #[cfg(target_os = "macos")]
    {
        macos_zero_word(addr)
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Empty maps in `arinsal-maps` point at a second arity-0 static. Any aligned
/// zero word inside a loaded image is that singleton: heap pointers are not
/// inside a Mach-O segment, so a dangling heap address still fails.
#[cfg(target_os = "macos")]
fn macos_zero_word(addr: usize) -> bool {
    if !addr.is_multiple_of(8) {
        return false;
    }
    let inside = image_ranges()
        .iter()
        .any(|&(start, end)| addr >= start && addr.saturating_add(8) <= end);
    if !inside {
        return false;
    }
    // SAFETY: `addr` is 8-aligned and lies inside a Mach-O segment mapped for
    // the life of the process. The load is one word and is not a heap access.
    unsafe { std::ptr::read(std::ptr::without_provenance::<u64>(addr)) == 0 }
}

#[cfg(target_os = "macos")]
fn image_ranges() -> &'static [(usize, usize)] {
    static RANGES: OnceLock<Vec<(usize, usize)>> = OnceLock::new();
    RANGES.get_or_init(collect_image_ranges)
}

#[cfg(target_os = "macos")]
fn collect_image_ranges() -> Vec<(usize, usize)> {
    unsafe extern "C" {
        fn _dyld_image_count() -> u32;
        fn _dyld_get_image_header(image_index: u32) -> *const u8;
        fn _dyld_get_image_vmaddr_slide(image_index: u32) -> isize;
    }
    let mut ranges = Vec::new();
    // SAFETY: dyld reports images mapped into this process.
    let count = unsafe { _dyld_image_count() };
    for index in 0..count {
        // SAFETY: `index` is below the count dyld just returned.
        let header = unsafe { _dyld_get_image_header(index) };
        if header.is_null() {
            continue;
        }
        // SAFETY: the header pointer is the mapped Mach-O header for `index`.
        let slide = unsafe { _dyld_get_image_vmaddr_slide(index) };
        // SAFETY: a non-null dyld header is at least four mapped bytes.
        let magic = unsafe { std::ptr::read_unaligned(header.cast::<u32>()) };
        if magic != 0xfeedfacf {
            continue;
        }
        // SAFETY: `MH_MAGIC_64` fixes `ncmds` and `sizeofcmds` at these offsets.
        let (ncmds, sizeofcmds) = unsafe {
            (
                std::ptr::read_unaligned(header.add(16).cast::<u32>()),
                std::ptr::read_unaligned(header.add(20).cast::<u32>()),
            )
        };
        // SAFETY: a 64-bit Mach-O header is 32 bytes; load commands follow it.
        let mut command = unsafe { header.add(32) };
        let mut left = sizeofcmds as usize;
        for _ in 0..ncmds {
            if left < 8 {
                break;
            }
            // SAFETY: `left` is the unread tail of the header's load-command blob.
            let (cmd, cmdsize) = unsafe {
                (
                    std::ptr::read_unaligned(command.cast::<u32>()),
                    std::ptr::read_unaligned(command.add(4).cast::<u32>()) as usize,
                )
            };
            if cmdsize < 8 || cmdsize > left {
                break;
            }
            // LC_SEGMENT_64 is 0x19. vmaddr/vmsize sit at bytes 24/32.
            // initprot at byte 60; skip segments that are not readable
            // (`__PAGEZERO` is mapped in the header but faults on load).
            if cmd == 0x19 && cmdsize >= 72 {
                // SAFETY: `cmdsize` covers the segment fields read below.
                let (vmaddr, vmsize, initprot) = unsafe {
                    (
                        std::ptr::read_unaligned(command.add(24).cast::<u64>()),
                        std::ptr::read_unaligned(command.add(32).cast::<u64>()),
                        std::ptr::read_unaligned(command.add(60).cast::<i32>()),
                    )
                };
                if vmsize > 0 && initprot & 1 != 0 {
                    let start = (vmaddr as usize).wrapping_add(slide as usize);
                    let end = start.saturating_add(vmsize as usize);
                    if end > start {
                        ranges.push((start, end));
                    }
                }
            }
            // SAFETY: `cmdsize` was bounded by the remaining load-command bytes.
            command = unsafe { command.add(cmdsize) };
            left -= cmdsize;
        }
    }
    ranges
}

fn accepted(heap: &ProcessHeap, term: Term) -> bool {
    if !term.is_pointer() {
        return true;
    }
    let addr = (term.0 & !7) as usize;
    heap_contains(heap, addr) || stable_contains(addr) || is_static_empty_tuple(addr)
}

fn describe(heap: &ProcessHeap) -> String {
    let young = describe_block(
        heap.words.as_ptr() as usize,
        heap.words.len(),
        heap.htop_index(),
        heap.stop_index(),
    );
    let old = if heap.old_words.is_empty() {
        "<empty>".to_owned()
    } else {
        let start = heap.old_words.as_ptr() as usize;
        let end = start + heap.old_words.len() * 8;
        let used = start + heap.old_htop * 8;
        format!("{start:#x}..{end:#x} used={start:#x}..{used:#x}")
    };
    let fragments = if heap.fragments.is_empty() {
        "<none>".to_owned()
    } else {
        heap.fragments
            .iter()
            .enumerate()
            .map(|(index, fragment)| {
                let start = fragment.as_ptr() as usize;
                let end = start + heap.fragment_used_words(index, fragment) * 8;
                format!("{start:#x}..{end:#x}")
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "young: {young}\n  old: {old}\n  fragments: {fragments}\n  stable_heaps: {}",
        stable_count()
    )
}

fn describe_block(start: usize, words: usize, htop: usize, stop: usize) -> String {
    if words == 0 {
        return "<empty>".to_owned();
    }
    let end = start + words * 8;
    let used = start + htop * 8;
    let stack = start + stop * 8;
    format!("{start:#x}..{end:#x} used={start:#x}..{used:#x} stack={stack:#x}..{end:#x}")
}

fn fail(heap: &ProcessHeap, term: Term, context: &str) -> ! {
    let word = term.0;
    let ranges = describe(heap);
    panic!("term validation failed\n  word: {word:#x}\n  context: {context}\n  {ranges}");
}

#[cfg(test)]
pub(crate) fn check_term(heap: &ProcessHeap, term: Term, context: &str) {
    if accepted(heap, term) {
        return;
    }
    fail(heap, term, context);
}

/// Check one term load. Immediates and an inactive checker return.
#[inline(always)]
pub fn check_if_active(heap: &ProcessHeap, term: Term) {
    if !active() || !term.is_pointer() {
        return;
    }
    if accepted(heap, term) {
        return;
    }
    fail(heap, term, &context_label(""));
}

/// Check every pointer reachable through cons cells and tuples of `term` (debug builds with
/// validation active). A message about to be copied must only name live allocations; the
/// first dangling child is reported with the path depth so the step that left it stale can be
/// named. Not an erts function: erts relies on `erts_check_heap` in debug builds.
pub fn check_deep_if_active(heap: &ProcessHeap, term: Term, context: &str) {
    if !active() || !term.is_pointer() {
        return;
    }
    let mut stack = vec![term];
    let mut seen = 0usize;
    while let Some(t) = stack.pop() {
        if !t.is_pointer() {
            continue;
        }
        seen += 1;
        if seen > 4_000_000 {
            return;
        }
        if !accepted(heap, t) {
            fail(
                heap,
                t,
                &format!("{context} (deep, after {seen} nodes, root {:#x})", term.0),
            );
        }
        let ptr = (t.0 & !7) as *const u64;
        // SAFETY: `accepted` just confirmed `ptr` lies in a live allocation.
        unsafe {
            if t.0 & 3 == 1 {
                stack.push(Term(*ptr));
                stack.push(Term(*ptr.add(1)));
            } else if t.0 & 3 == 2 && is_static_empty_tuple(ptr as usize) {
                continue;
            } else if t.0 & 3 == 2 && *ptr & 63 == crate::ARITY {
                let n = (*ptr >> 6) as usize;
                for i in 1..=n {
                    stack.push(Term(*ptr.add(i)));
                }
            }
        }
    }
}

/// Check every root the collector just rewrote, including the live stack.
#[inline]
pub fn check_roots_if_active(heap: &ProcessHeap, roots: &[Term], extra: &[Term]) {
    if !active() {
        return;
    }
    let context = context_label("after GC");
    for (index, term) in roots.iter().copied().enumerate() {
        if !accepted(heap, term) {
            fail(heap, term, &format!("{context} root[{index}]"));
        }
    }
    for (index, term) in extra.iter().copied().enumerate() {
        if !accepted(heap, term) {
            fail(heap, term, &format!("{context} extra[{index}]"));
        }
    }
    for index in 0..heap.stack_words() {
        let Some(word) = heap.words.get(heap.stop_index() + index) else {
            continue;
        };
        // SAFETY: `stack_words` counts the live suffix; the collector initialized it.
        let term = Term(unsafe { *word.get() });
        if !accepted(heap, term) {
            fail(heap, term, &format!("{context} stack[{index}]"));
        }
    }
}

/// Verify every root after collection in debug builds, even when load-time
/// term validation is disabled.
#[cfg(debug_assertions)]
pub(crate) fn verify_roots_after_collection(heap: &ProcessHeap, roots: &[Term], extra: &[Term]) {
    if !gc_verify_active() {
        return;
    }
    let context = context_label("after GC");
    for (index, term) in roots.iter().copied().enumerate() {
        if !accepted(heap, term) {
            fail(heap, term, &format!("{context} root[{index}]"));
        }
    }
    for (index, term) in extra.iter().copied().enumerate() {
        if !accepted(heap, term) {
            fail(heap, term, &format!("{context} extra[{index}]"));
        }
    }
    for index in 0..heap.stack_words() {
        let Some(term) = heap.stack_get(index) else {
            continue;
        };
        if !accepted(heap, term) {
            fail(heap, term, &format!("{context} stack[{index}]"));
        }
    }
}

#[cfg(debug_assertions)]
pub(crate) fn verify_copied_term_after_collection(heap: &ProcessHeap, term: Term) {
    if gc_verify_active() && !accepted(heap, term) {
        fail(heap, term, "after GC heap field");
    }
}

/// The used areas of a process heap: young `0..htop`, old `0..old_htop` and every fragment.
fn used_areas(heap: &ProcessHeap) -> Vec<(usize, usize, &'static str)> {
    let mut areas = Vec::new();
    let young = heap.words.as_ptr() as usize;
    if !heap.words.is_empty() {
        areas.push((young, young + heap.htop_index() * 8, "young"));
    }
    let old = heap.old_words.as_ptr() as usize;
    if !heap.old_words.is_empty() {
        areas.push((old, old + heap.old_htop * 8, "old"));
    }
    for (index, fragment) in heap.fragments.iter().enumerate() {
        let start = fragment.as_ptr() as usize;
        areas.push((
            start,
            start + heap.fragment_used_words(index, fragment) * 8,
            "fragment",
        ));
    }
    areas
}

fn area_of(areas: &[(usize, usize, &'static str)], address: usize) -> Option<&'static str> {
    areas
        .iter()
        .find(|&&(start, end, _)| address >= start && address < end)
        .map(|&(_, _, name)| name)
}

/// Check the writable-binary structure of a process heap (debug builds with validation
/// active): every `SUB_BITS` `orig` names a `BinRef` or heap-bits header in a used heap area
/// or a literal, no old-generation object points into the young generation, and every
/// `wrt_bins` node is a `BinRef` in a used heap area. Not an erts function: erts checks the
/// same heap shape in debug builds with `erts_check_heap` and `disallow_heap_frag_ref_in_old_heap`.
pub fn check_heap_bits_if_active(heap: &ProcessHeap, context: &str) {
    if !active() {
        return;
    }
    let areas = used_areas(heap);
    let literals = crate::literal::literal_area();
    let valid_target = |address: usize| -> Result<&'static str, String> {
        let area = if let Some(area) = area_of(&areas, address) {
            area
        } else if address >= literals.0 && address < literals.1 || stable_contains(address) {
            "literal"
        } else {
            return Err(format!("{address:#x} outside every used heap area"));
        };
        let header = crate::raw::load(address);
        if header & 3 != 0 || !matches!(header & 63, crate::BIN_REF | crate::HEAP_BITS) {
            return Err(format!(
                "{address:#x} ({area}) has header {header:#x}, not BinRef/heap bits"
            ));
        }
        Ok(area)
    };
    for &(start, end, name) in &areas {
        let mut at = start;
        while at < end {
            let word = crate::raw::load(at);
            if word & 3 != 0 {
                at += 8;
                continue;
            }
            let words = if word & 63 == crate::ARITY || word & 63 == crate::RECORD {
                1 + (word >> 6) as usize
            } else {
                crate::raw::boxed_words(word, at)
            };
            if word & 63 == crate::SUB_BITS {
                let orig = crate::raw::load(at + 32);
                let result = if orig & 3 != 2 {
                    Err(format!("orig {orig:#x} is not boxed"))
                } else {
                    valid_target((orig & !7) as usize)
                };
                match result {
                    Ok(target) if name == "old" && matches!(target, "young" | "fragment") => {
                        panic!(
                            "heap bits validation failed ({context}): old SUB_BITS at {at:#x} \
                             has orig {orig:#x} in {target}\n  {}",
                            describe(heap)
                        );
                    }
                    Ok(_) => {}
                    Err(error) => panic!(
                        "heap bits validation failed ({context}): SUB_BITS at {at:#x} ({name}) \
                         flags {:#x}: {error}\n  {}",
                        crate::raw::load(at + 8) & 3,
                        describe(heap)
                    ),
                }
            }
            at += words.max(1) * 8;
        }
    }
    if !heap.old_generation_is_closed() {
        panic!(
            "heap bits validation failed ({context}): the old generation points into the \
             young generation\n  {}",
            describe(heap)
        );
    }
    let (_, mut node) = heap.owners.chain_heads();
    let mut count = 0usize;
    while node != 0 {
        let header = if area_of(&areas, node).is_some() {
            crate::raw::load(node)
        } else {
            0
        };
        if header & 3 != 0 || header & 63 != crate::BIN_REF {
            panic!(
                "heap bits validation failed ({context}): wrt_bins node {node:#x} #{count} \
                 (area {:?}) has header {header:#x}\n  {}",
                area_of(&areas, node),
                describe(heap)
            );
        }
        node = crate::raw::load(node + 16) as usize;
        count += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::check_term;
    use crate::{ProcessHeap, Term, TermBuilder, VecHeap};

    #[test]
    fn immediates_and_heap_pointers_pass() {
        let mut heap = ProcessHeap::with_words(64);
        let list = TermBuilder::new(&mut heap)
            .cons(Term::small(1).unwrap(), Term::NIL)
            .unwrap();
        let empty = TermBuilder::new(&mut heap).tuple(&[]).unwrap();
        check_term(&heap, Term::NIL, "term:imm/0 move");
        check_term(&heap, Term::small(3).unwrap(), "term:imm/0 move");
        check_term(&heap, list, "term:imm/0 move");
        check_term(&ProcessHeap::new(), empty, "term:empty/0 move");
    }

    #[test]
    fn literal_and_fragment_pointers_pass() {
        let mut literals = VecHeap::new();
        let literal = TermBuilder::new(&mut literals)
            .tuple(&[Term::small(7).unwrap()])
            .unwrap();
        let heap = ProcessHeap::with_words(64);
        check_term(&heap, literal, "lit:mod/0 move");

        let mut owner = ProcessHeap::with_words(64);
        let raw = owner.heap_fragment(2);
        // SAFETY: the fragment reserves two words and stays live until `owner` drops.
        unsafe {
            *raw = Term::small(1).unwrap().0;
            *raw.add(1) = Term::NIL.0;
        }
        let fragment_term = Term::from_ptr(raw, 1);
        check_term(&owner, fragment_term, "frag:bif/2 move");
    }

    #[test]
    fn roots_after_collection_stay_in_the_new_heap() {
        let mut heap = ProcessHeap::with_words(128);
        let term = TermBuilder::new(&mut heap)
            .cons(Term::small(1).unwrap(), Term::NIL)
            .unwrap();
        let mut roots = [term];
        heap.collect(&mut roots, &mut [], 0).unwrap();
        check_term(&heap, roots[0], "gc:root/1 after GC");
    }

    #[test]
    fn dangling_pointer_reports_word_context_and_ranges() {
        let heap = ProcessHeap::new();
        let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_term(&heap, Term(0x1002), "demo:run/0 move");
        }))
        .expect_err("dangling boxed pointer");
        let message = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .unwrap_or("");
        assert!(message.contains("word: 0x1002"), "{message}");
        assert!(message.contains("context: demo:run/0 move"), "{message}");
        assert!(message.contains("young:"), "{message}");
        assert!(message.contains("old:"), "{message}");
        assert!(message.contains("fragments:"), "{message}");
    }

    #[test]
    fn inactive_checker_ignores_dangling_pointers() {
        if super::active() {
            return;
        }
        let heap = ProcessHeap::new();
        super::check_if_active(&heap, Term(0x1002));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn nonzero_image_word_is_not_an_empty_tuple() {
        static NONZERO: u64 = 0x11;
        let heap = ProcessHeap::new();
        let term = Term((std::ptr::from_ref(&NONZERO) as u64) | 2);
        let error = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            check_term(&heap, term, "term:static/0 move");
        }))
        .expect_err("nonzero static");
        let message = error.downcast_ref::<String>().map(String::as_str).unwrap();
        assert!(message.contains("term:static/0 move"), "{message}");
    }
}
