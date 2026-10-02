//! Literal-aware copying keeps literal-area references (copy.c litopt semantics).

use arinsal_term::{
    LiteralArea, LiteralAreas, Term, TermBuilder, VecHeap, copy_shared, copy_term,
    copy_term_litopt, set_literal_purge_area, size_object, size_object_litopt, size_shared,
};

fn small(n: i64) -> Term {
    Term::small(n).unwrap()
}

/// A literal `{[1,2], 1.5}` plus a heap term `{Lit, [Lit | Lit]}` that references it.
fn fixture(area: &mut LiteralArea, heap: &mut VecHeap) -> (Term, Term) {
    let literal = {
        let mut builder = area.builder();
        let list = builder.list_from_slice(&[small(1), small(2)]).unwrap();
        let float = builder.float(1.5).unwrap();
        builder.tuple(&[list, float]).unwrap()
    };
    let mut builder = TermBuilder::new(heap);
    let improper = builder.cons(literal, literal).unwrap();
    let outer = builder.tuple(&[literal, improper]).unwrap();
    (literal, outer)
}

fn element(tuple: Term, index: usize) -> Term {
    // SAFETY: the fixtures only pass live tuples owned by a heap in scope.
    unsafe { tuple.tuple_ref() }
        .unwrap()
        .get(index - 1)
        .unwrap()
}

fn cons(cell: Term) -> (Term, Term) {
    // SAFETY: the fixtures only pass live cons cells owned by a heap in scope.
    unsafe { cell.cons_ref() }.unwrap()
}

#[test]
fn litopt_copy_keeps_literal_references() {
    let mut area = LiteralArea::new();
    let mut source = VecHeap::new();
    let (literal, outer) = fixture(&mut area, &mut source);
    assert!(literal.is_literal());
    let literals = LiteralAreas::current();
    // Only the outer 3-word tuple and the 2-word cons are copied.
    assert_eq!(size_object_litopt(outer, &literals), 5);
    assert_eq!(size_object_litopt(literal, &literals), 0);
    let mut target = VecHeap::new();
    let copy = copy_term_litopt(outer, &mut target, &literals).unwrap();
    assert_ne!(copy, outer);
    assert_eq!(element(copy, 1), literal);
    assert_eq!(cons(element(copy, 2)), (literal, literal));
    // A plain copy duplicates every literal occurrence (`size_object` without litopt).
    assert_eq!(size_object(outer), 5 + 3 * size_object(literal));
    let mut full_heap = VecHeap::new();
    let full = copy_term(outer, &mut full_heap).unwrap();
    assert_ne!(element(full, 1), literal);
    // size_shared counts the heap part once and ignores literals.
    assert_eq!(size_shared(outer), 5);
    assert_eq!(size_shared(literal), 0);
}

#[test]
fn purge_area_literals_are_copied() {
    let mut area = LiteralArea::new();
    let mut source = VecHeap::new();
    let (literal, outer) = fixture(&mut area, &mut source);
    let ranges = area.pointer_ranges();
    set_literal_purge_area(&ranges, true);
    let literals = LiteralAreas::current();
    set_literal_purge_area(&ranges, false);
    assert_eq!(size_object_litopt(outer, &literals), size_object(outer));
    let mut target = VecHeap::new();
    let copy = copy_term_litopt(outer, &mut target, &literals).unwrap();
    assert!(!element(copy, 1).is_literal());
    assert_ne!(element(copy, 1), literal);
    // A fresh snapshot shares the area again.
    assert_eq!(size_object_litopt(outer, &LiteralAreas::current()), 5);
}

#[test]
fn copy_shared_honours_copy_literals() {
    let mut area = LiteralArea::new();
    let mut source = VecHeap::new();
    let (literal, outer) = fixture(&mut area, &mut source);
    let mut shared_heap = VecHeap::new();
    let shared = copy_shared(outer, &mut shared_heap, false).unwrap();
    assert_eq!(element(shared, 1), literal);
    let mut copied_heap = VecHeap::new();
    let copied = copy_shared(outer, &mut copied_heap, true).unwrap();
    let inner = element(copied, 1);
    assert!(!inner.is_literal());
    // As in erts, copied literals are not shared: each occurrence gets its own copy.
    let (head, tail) = cons(element(copied, 2));
    assert!(head != inner && tail != inner && head != tail);
    assert_eq!(size_shared(copied), 5 + 3 * size_object(literal));
}

#[test]
fn literal_registry_forgets_dropped_areas() {
    let mut area = LiteralArea::with_capacity_words(8);
    let literal = area.builder().tuple(&[small(1)]).unwrap();
    assert!(literal.is_literal());
    let address = literal.tagged_word() & !7;
    drop(area);
    assert!(!LiteralAreas::current().is_literal(address));
}
