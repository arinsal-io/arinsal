//! Release micro gate for `=:=`, `==` and `<` on the shapes the compiler compares most.
//! Run with `cargo test -p arinsal-term --release --test eq_shapes_perf -- --ignored --nocapture`.

use arinsal_term::{
    HeapAlloc, ProcessHeap, Term, TermBuilder, cmp, exact_eq, global_atoms, loose_eq,
};
use std::hint::black_box;
use std::time::Instant;

fn atom(name: &str) -> Term {
    Term::atom(global_atoms().intern(name).unwrap())
}

fn small(n: i64) -> Term {
    Term::small(n).unwrap()
}

struct Pair {
    name: &'static str,
    left: Term,
    right: Term,
}

/// Two structurally equal copies built separately, so no subterm is pointer-identical.
fn var<H: HeapAlloc + ?Sized>(b: &mut TermBuilder<'_, H>, n: i64) -> Term {
    let name = b.tuple(&[atom("@ssa_var"), small(n)]).unwrap();
    b.tuple(&[atom("b_var"), name]).unwrap()
}

fn build(heap: &mut ProcessHeap, variant: u8) -> Vec<Term> {
    let mut b = TermBuilder::new(heap);
    let tuple = b
        .tuple(&[
            atom("a"),
            small(1),
            atom("b"),
            small(2),
            atom("c"),
            small(3),
        ])
        .unwrap();
    let record = b
        .tuple(&[atom("rec"), atom("foo"), small(42), atom("bar")])
        .unwrap();
    let args = {
        let v1 = var(&mut b, 8);
        let lit = b.tuple(&[atom("b_literal"), small(1)]).unwrap();
        let ctx = b.tuple(&[atom("b_var"), atom("ctx")]).unwrap();
        b.list_from_iter([v1, lit, ctx]).unwrap()
    };
    let dst = var(&mut b, 7);
    let anno = b.flatmap_from_pairs(&[]).unwrap();
    let ssa = b
        .tuple(&[atom("b_set"), anno, dst, atom("bs_get_tail"), args])
        .unwrap();
    let list = b
        .list_from_iter(["a", "b", "c", "d", "e", "f"].into_iter().map(atom))
        .unwrap();
    let ints = b.list_from_iter((1..=8).map(small)).unwrap();
    let map = b
        .flatmap_from_pairs(&[
            (atom("a"), small(1)),
            (atom("b"), small(2)),
            (atom("c"), small(3)),
            (atom("d"), small(4)),
            (atom("e"), small(5)),
        ])
        .unwrap();
    // `variant` 1 differs at the first element, 2 at the last, 0 not at all.
    let first = b
        .tuple(&[
            atom(if variant == 1 { "y" } else { "x" }),
            small(2),
            small(3),
            small(4),
            small(5),
            small(6),
            small(7),
            small(8),
        ])
        .unwrap();
    let last = b
        .tuple(&[
            small(1),
            small(2),
            small(3),
            small(4),
            small(5),
            small(6),
            small(7),
            small(if variant == 2 { 9 } else { 8 }),
        ])
        .unwrap();
    let ssa_last = {
        let v1 = var(&mut b, if variant == 2 { 9 } else { 8 });
        let lit = b.tuple(&[atom("b_literal"), small(1)]).unwrap();
        let ctx = b.tuple(&[atom("b_var"), atom("ctx")]).unwrap();
        let args = b.list_from_iter([v1, lit, ctx]).unwrap();
        let dst = var(&mut b, 7);
        let anno = b.flatmap_from_pairs(&[]).unwrap();
        b.tuple(&[atom("b_set"), anno, dst, atom("bs_get_tail"), args])
            .unwrap()
    };
    vec![tuple, record, ssa, list, map, ints, first, last, ssa_last]
}

#[test]
#[ignore = "release micro gate"]
fn eq_shapes_micro_gate() {
    let mut left_heap = ProcessHeap::with_words(65_536);
    let mut right_heap = ProcessHeap::with_words(65_536);
    let names = [
        "tuple_eq",
        "record_eq",
        "ssa_eq",
        "list_eq",
        "map5_eq",
        "int_list_eq",
        "tuple_ne_first",
        "tuple_ne_last",
        "ssa_ne_last",
    ];
    let lefts = build(&mut left_heap, 0);
    let mut rights = build(&mut right_heap, 0);
    // The unequal shapes take the differing copy on the right.
    let ne = build(&mut right_heap, 1);
    rights[6] = ne[6];
    let ne = build(&mut right_heap, 2);
    rights[7] = ne[7];
    rights[8] = ne[8];
    let pairs: Vec<Pair> = names
        .iter()
        .zip(lefts.iter().zip(rights.iter()))
        .map(|(name, (left, right))| Pair {
            name,
            left: *left,
            right: *right,
        })
        .collect();
    const N: u32 = 2_000_000;
    println!(
        "{:<16} {:>8} {:>8} {:>8}  (ns/op)",
        "shape", "=:=", "==", "<"
    );
    // Floor: the same word on both sides, so only the harness and the `a == b` test run.
    {
        let l = pairs[0].left;
        let start = Instant::now();
        let mut hits = 0_u32;
        for _ in 0..N {
            hits += u32::from(exact_eq(black_box(l), black_box(l)));
        }
        black_box(hits);
        println!(
            "{:<16} {:>8.2}",
            "same_word",
            start.elapsed().as_secs_f64() * 1e9 / f64::from(N)
        );
    }
    for pair in &pairs {
        let (l, r) = (pair.left, pair.right);
        let time = |f: &dyn Fn(Term, Term) -> bool| {
            (0..7)
                .map(|_| {
                    let start = Instant::now();
                    let mut hits = 0_u32;
                    for _ in 0..N {
                        hits += u32::from(f(black_box(l), black_box(r)));
                    }
                    black_box(hits);
                    start.elapsed().as_secs_f64() * 1e9 / f64::from(N)
                })
                .fold(f64::INFINITY, f64::min)
        };
        let exact = time(&|a, b| exact_eq(a, b));
        let loose = time(&|a, b| loose_eq(a, b));
        let less = time(&|a, b| cmp(a, b).is_lt());
        println!("{:<16} {exact:>8.2} {loose:>8.2} {less:>8.2}", pair.name);
    }
}
