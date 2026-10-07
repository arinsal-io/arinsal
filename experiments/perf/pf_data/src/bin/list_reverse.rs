use arinsal_bifs::{Ctx, FragmentingHeap, lookup};
use arinsal_term::{ProcessHeap, Term, TermBuilder, TermKind, VecHeap};
use std::hint::black_box;
use std::time::Instant;

fn old_reverse(input: Term, output: &mut FragmentingHeap<'_>) -> Term {
    let mut source = input;
    let mut values = Vec::new();
    while source.classify() == TermKind::List {
        // SAFETY: the input heap stays live and does not move during this probe.
        let (head, next) = unsafe { source.cons_ref() }.unwrap();
        values.push(head);
        source = next;
    }
    let items: Vec<_> = values.into_iter().rev().collect();
    let mut builder = TermBuilder::new(output);
    let mut result = Term::NIL;
    for item in items.into_iter().rev() {
        result = builder.cons(item, result).unwrap();
    }
    result
}

fn main() {
    let mut input_heap = VecHeap::new();
    let input = TermBuilder::new(&mut input_heap)
        .list_from_iter((1..=10_000).map(|value| Term::small(value).unwrap()))
        .unwrap();
    let reverse = lookup("lists", "reverse", 2).unwrap();
    for _ in 0..3 {
        let mut output_heap = ProcessHeap::with_words(1_024);
        let mut output = FragmentingHeap(&mut output_heap);
        let start = Instant::now();
        for _ in 0..10 {
            black_box(old_reverse(input, &mut output));
        }
        println!(
            "old reverse 10: {:.3} ms",
            start.elapsed().as_secs_f64() * 1e3
        );

        let mut output_heap = ProcessHeap::with_words(1_024);
        let mut output = FragmentingHeap(&mut output_heap);
        let mut ctx = Ctx::new(&mut output);
        let start = Instant::now();
        for _ in 0..10 {
            black_box(reverse(&mut ctx, &[input, Term::NIL]).unwrap());
        }
        println!(
            "new reverse 10: {:.3} ms",
            start.elapsed().as_secs_f64() * 1e3
        );
    }
}
