use arinsal_term::{
    ProcessHeap, Term, TermBuilder, VecHeap, build_hamt_from_unique, copy_term, exact_eq,
    size_object,
};
use std::hint::black_box;
use std::time::Instant;

#[test]
#[ignore = "release micro gate; run with --release --ignored --nocapture"]
fn general_term_micro_gates() {
    fn median(mut samples: Vec<f64>) -> f64 {
        samples.sort_by(f64::total_cmp);
        samples[samples.len() / 2]
    }
    let entries: Vec<_> = (0..1_000)
        .map(|n| (Term::small(n).unwrap(), Term::small(n * 7).unwrap()))
        .collect();
    let mut left_heap = VecHeap::new();
    let mut right_heap = VecHeap::new();
    let left = build_hamt_from_unique(&entries, &mut left_heap).unwrap();
    let right = build_hamt_from_unique(&entries, &mut right_heap).unwrap();
    assert!(exact_eq(left, right));
    let mut reordered_heap = VecHeap::new();
    let reordered = build_hamt_from_unique(
        &entries.iter().copied().rev().collect::<Vec<_>>(),
        &mut reordered_heap,
    )
    .unwrap();
    assert!(exact_eq(left, reordered));

    let mut source_heap = ProcessHeap::with_words(131_136);
    let mut list = Term::NIL;
    for n in 0..65_536 {
        list = TermBuilder::new(&mut source_heap)
            .cons(Term::small(n).unwrap(), list)
            .unwrap();
    }
    let mut variant_heap = ProcessHeap::with_words(131_136);
    let variant = TermBuilder::new(&mut variant_heap)
        .list_from_iter((0..65_536).map(|n| Term::small(n * 3).unwrap()))
        .unwrap();
    let mut destination = ProcessHeap::with_words(131_136);
    let (base, _) = destination.heap_cursor();
    let mut equality = Vec::new();
    let mut reordered_equality = Vec::new();
    let mut sizing = Vec::new();
    let mut variant_sizing = Vec::new();
    let mut copying = Vec::new();
    let mut variant_copying = Vec::new();
    for _ in 0..7 {
        let start = Instant::now();
        for _ in 0..100 {
            black_box(exact_eq(black_box(left), black_box(right)));
        }
        equality.push(start.elapsed().as_secs_f64() * 1e6 / 100.0);

        let start = Instant::now();
        for _ in 0..100 {
            black_box(exact_eq(black_box(left), black_box(reordered)));
        }
        reordered_equality.push(start.elapsed().as_secs_f64() * 1e6 / 100.0);

        let start = Instant::now();
        for _ in 0..100 {
            black_box(size_object(black_box(list)));
        }
        sizing.push(start.elapsed().as_secs_f64() * 1e6 / 100.0);

        let start = Instant::now();
        for _ in 0..100 {
            black_box(size_object(black_box(variant)));
        }
        variant_sizing.push(start.elapsed().as_secs_f64() * 1e6 / 100.0);

        let start = Instant::now();
        for _ in 0..100 {
            black_box(copy_term(black_box(list), &mut destination).unwrap());
            destination.set_heap_top(base);
        }
        copying.push(start.elapsed().as_secs_f64() * 1e6 / 100.0);

        let start = Instant::now();
        for _ in 0..100 {
            black_box(copy_term(black_box(variant), &mut destination).unwrap());
            destination.set_heap_top(base);
        }
        variant_copying.push(start.elapsed().as_secs_f64() * 1e6 / 100.0);
    }
    eprintln!("map equality 1000: {:.2} us", median(equality));
    eprintln!(
        "map equality reordered: {:.2} us",
        median(reordered_equality)
    );
    eprintln!("size_object 65536 cons: {:.2} us", median(sizing));
    eprintln!(
        "size_object list_from_iter: {:.2} us",
        median(variant_sizing)
    );
    eprintln!("copy_term 65536 cons: {:.2} us", median(copying));
    eprintln!(
        "copy_term list_from_iter: {:.2} us",
        median(variant_copying)
    );
}
