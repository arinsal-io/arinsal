use arinsal_term::{
    ProcessHeap, Term, TermBuilder, VecHeap, build_hamt_from_unique, cmp_exact, copy_term,
    exact_eq, global_atoms, loose_eq, size_object,
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

#[test]
#[ignore = "10M alternating term equality and comparison measurements"]
fn equality_and_comparison_microbench_10m() {
    const N: usize = 10_000_000;
    const ROUNDS: usize = 3;

    struct Case {
        name: &'static str,
        equal: (Term, Term),
        compare: (Term, Term),
    }

    fn sequence(heap: &mut VecHeap, count: usize, last: Option<i64>) -> Term {
        let mut values = (1..=count)
            .map(|value| Term::small(value as i64).unwrap())
            .collect::<Vec<_>>();
        if let Some(value) = last {
            *values.last_mut().unwrap() = Term::small(value).unwrap();
        }
        TermBuilder::new(heap).list_from_iter(values).unwrap()
    }

    fn sequence_first(heap: &mut VecHeap, count: usize) -> Term {
        TermBuilder::new(heap)
            .list_from_iter(
                (0..count).map(|index| {
                    Term::small(if index == 0 { 0 } else { index as i64 + 1 }).unwrap()
                }),
            )
            .unwrap()
    }

    fn tuple(heap: &mut VecHeap, count: usize, last: Option<i64>) -> Term {
        let mut values = (1..=count)
            .map(|value| Term::small(value as i64).unwrap())
            .collect::<Vec<_>>();
        if let Some(value) = last {
            *values.last_mut().unwrap() = Term::small(value).unwrap();
        }
        TermBuilder::new(heap).tuple(&values).unwrap()
    }

    fn nest(heap: &mut VecHeap, mut term: Term, depth: usize) -> Term {
        let tag = Term::small(1).unwrap();
        for _ in 0..depth {
            term = TermBuilder::new(heap).tuple(&[tag, term]).unwrap();
        }
        term
    }

    fn maps(heap: &mut VecHeap, count: i64, last: Option<i64>) -> Term {
        let pairs = (1..=count)
            .map(|key| {
                (
                    Term::small(key).unwrap(),
                    Term::small(if key == count {
                        last.unwrap_or(key)
                    } else {
                        key
                    })
                    .unwrap(),
                )
            })
            .collect::<Vec<_>>();
        TermBuilder::new(heap).flatmap_from_pairs(&pairs).unwrap()
    }

    let mut heap = VecHeap::new();
    let list = sequence(&mut heap, 8, None);
    let list_equal = sequence(&mut heap, 8, None);
    let list_different = sequence(&mut heap, 8, Some(0));
    let tuple_term = tuple(&mut heap, 8, None);
    let tuple_equal = tuple(&mut heap, 8, None);
    let tuple_different = tuple(&mut heap, 8, Some(0));
    let nested = nest(&mut heap, list, 6);
    let nested_equal = nest(&mut heap, list_equal, 6);
    let nested_different = nest(&mut heap, list_different, 6);
    let map = maps(&mut heap, 8, None);
    let map_equal = maps(&mut heap, 8, None);
    let map_different = maps(&mut heap, 8, Some(0));
    assert!(!map.is_hashmap(), "the OTP 8-entry fixture is a flatmap");
    let nested_key = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(Term::small(1).unwrap(), Term::small(1).unwrap())])
        .unwrap();
    let nested_key_equal = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(Term::small(1).unwrap(), Term::small(1).unwrap())])
        .unwrap();
    let nested_key_different = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(Term::small(1).unwrap(), Term::small(2).unwrap())])
        .unwrap();
    let nested_key_map = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(nested_key, Term::small(0).unwrap())])
        .unwrap();
    let nested_key_map_equal = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(nested_key_equal, Term::small(0).unwrap())])
        .unwrap();
    let nested_key_map_different = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[(nested_key_different, Term::small(0).unwrap())])
        .unwrap();
    let hamt_pairs = (1..=40)
        .map(|key| (Term::small(key).unwrap(), Term::small(key).unwrap()))
        .collect::<Vec<_>>();
    let hamt = build_hamt_from_unique(&hamt_pairs, &mut heap).unwrap();
    let hamt_equal = build_hamt_from_unique(&hamt_pairs, &mut heap).unwrap();
    let hamt_different_pairs = (1..=40)
        .map(|key| {
            (
                Term::small(key).unwrap(),
                Term::small(if key == 40 { 0 } else { key }).unwrap(),
            )
        })
        .collect::<Vec<_>>();
    let hamt_different = build_hamt_from_unique(&hamt_different_pairs, &mut heap).unwrap();
    assert!(hamt.is_hashmap(), "the OTP 40-entry fixture is a HAMT");
    let atom_a = Term::atom(global_atoms().intern("eq_cmp_bench_alpha").unwrap());
    let atom_b = Term::atom(global_atoms().intern("eq_cmp_bench_beta").unwrap());
    let tuple_atoms = [atom_a; 10];
    let tuple_atoms_term = TermBuilder::new(&mut heap).tuple(&tuple_atoms).unwrap();
    let tuple_atoms_equal = TermBuilder::new(&mut heap).tuple(&tuple_atoms).unwrap();
    let tuple_atoms_different = TermBuilder::new(&mut heap)
        .tuple(&[
            atom_b, atom_a, atom_a, atom_a, atom_a, atom_a, atom_a, atom_a, atom_a, atom_a,
        ])
        .unwrap();
    let list100 = sequence(&mut heap, 100, None);
    let list100_equal = sequence(&mut heap, 100, None);
    let list100_different_first = sequence_first(&mut heap, 100);
    let map10 = maps(&mut heap, 10, None);
    let map10_equal = maps(&mut heap, 10, None);
    let map10_different_first = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(
            &(1..=10)
                .map(|key| {
                    (
                        Term::small(key).unwrap(),
                        Term::small(if key == 1 { 0 } else { key }).unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let atom_a_equal = Term::atom(global_atoms().intern("eq_cmp_bench_alpha").unwrap());
    let atom_b_equal = Term::atom(global_atoms().intern("eq_cmp_bench_beta").unwrap());
    let selected_cases = std::env::var("EQ_STACK_BENCH_CASE")
        .expect("set EQ_STACK_BENCH_CASE to a comma-separated case list");
    let cases = vec![
        Case {
            name: "list",
            equal: (list, list_equal),
            compare: (list, list_different),
        },
        Case {
            name: "tuple",
            equal: (tuple_term, tuple_equal),
            compare: (tuple_term, tuple_different),
        },
        Case {
            name: "nested",
            equal: (nested, nested_equal),
            compare: (nested, nested_different),
        },
        Case {
            name: "map",
            equal: (map, map_equal),
            compare: (map, map_different),
        },
        Case {
            name: "nested_key",
            equal: (nested_key_map, nested_key_map_equal),
            compare: (nested_key_map, nested_key_map_different),
        },
        Case {
            name: "hamt40",
            equal: (hamt, hamt_equal),
            compare: (hamt, hamt_different),
        },
        Case {
            name: "small_atoms",
            equal: (atom_a, atom_a_equal),
            compare: (atom_a, atom_b_equal),
        },
        Case {
            name: "tuple10_atoms",
            equal: (tuple_atoms_term, tuple_atoms_equal),
            compare: (tuple_atoms_term, tuple_atoms_different),
        },
        Case {
            name: "list100",
            equal: (list100, list100_equal),
            compare: (list100, list100_different_first),
        },
        Case {
            name: "map10",
            equal: (map10, map10_equal),
            compare: (map10, map10_different_first),
        },
        Case {
            name: "unequal_first",
            equal: (list100, list100_equal),
            compare: (list100, list100_different_first),
        },
    ]
    .into_iter()
    .filter(|case| selected_cases.split(',').any(|name| name == case.name))
    .collect::<Vec<_>>();
    similar_asserts::assert_eq!(
        cases.len(),
        selected_cases.split(',').count(),
        "unknown EQ_STACK_BENCH_CASE"
    );
    for case in &cases {
        assert!(
            exact_eq(case.equal.0, case.equal.1),
            "{} exact equality",
            case.name
        );
        assert!(
            loose_eq(case.equal.0, case.equal.1),
            "{} loose equality",
            case.name
        );
        similar_asserts::assert_eq!(
            cmp_exact(case.compare.0, case.compare.1).is_eq(),
            false,
            "{} comparison pair must differ",
            case.name
        );
    }

    fn rust_measure(left: Term, right: Term, operation: impl Fn(Term, Term) -> i32) -> f64 {
        let start = Instant::now();
        for index in 0..N {
            let (left, right) = if index & 1 == 0 {
                (left, right)
            } else {
                (right, left)
            };
            black_box(operation(black_box(left), black_box(right)));
        }
        start.elapsed().as_secs_f64() * 1e9 / N as f64
    }

    fn rust_empty_loop(left: Term, right: Term) -> f64 {
        let start = Instant::now();
        for index in 0..N {
            let pair = if index & 1 == 0 {
                (left, right)
            } else {
                (right, left)
            };
            black_box(pair);
        }
        start.elapsed().as_secs_f64() * 1e9 / N as f64
    }

    fn rust_round(cases: &[Case]) -> Vec<(f64, f64, f64)> {
        let empty = rust_empty_loop(cases[0].equal.0, cases[0].equal.1);
        cases
            .iter()
            .map(|case| {
                let eq = rust_measure(case.equal.0, case.equal.1, |a, b| i32::from(exact_eq(a, b)))
                    - empty;
                let loose =
                    rust_measure(case.equal.0, case.equal.1, |a, b| i32::from(loose_eq(a, b)))
                        - empty;
                let order = rust_measure(case.compare.0, case.compare.1, |a, b| {
                    match cmp_exact(a, b) {
                        std::cmp::Ordering::Less => -1,
                        std::cmp::Ordering::Equal => 0,
                        std::cmp::Ordering::Greater => 1,
                    }
                }) - empty;
                (eq, loose, order)
            })
            .collect()
    }

    let reference_module = r#"
-module(eq_stack_bench).
-export([run/1]).
run(Names) ->
    List = lists:seq(1, 8),
    ListEqual = lists:reverse(lists:reverse(List)),
    ListDifferent = lists:seq(1, 7) ++ [0],
    Tuple = list_to_tuple(List),
    TupleEqual = list_to_tuple(List),
    TupleDifferent = list_to_tuple(lists:seq(1, 7) ++ [0]),
    Deep = lists:foldl(fun(_, Acc) -> {1, Acc} end, List, lists:seq(1, 6)),
    DeepEqual = lists:foldl(fun(_, Acc) -> {1, Acc} end, ListEqual, lists:seq(1, 6)),
    DeepDifferent = lists:foldl(fun(_, Acc) -> {1, Acc} end, ListDifferent, lists:seq(1, 6)),
    Map = maps:from_list([{K, K} || K <- lists:seq(1, 8)]),
    MapEqual = maps:from_list([{K, K} || K <- lists:seq(1, 8)]),
    MapDifferent = maps:from_list([{K, if K == 8 -> 0; true -> K end}
                                   || K <- lists:seq(1, 8)]),
    SmallAtom = eq_cmp_bench_alpha,
    SmallAtomOther = eq_cmp_bench_beta,
    Tuple10Atoms = list_to_tuple(lists:duplicate(10, SmallAtom)),
    Tuple10AtomsDifferent = list_to_tuple([SmallAtomOther | lists:duplicate(9, SmallAtom)]),
    List100 = lists:seq(1, 100),
    List100DifferentFirst = [0 | lists:seq(2, 100)],
    Map10 = maps:from_list([{K, K} || K <- lists:seq(1, 10)]),
    Map10DifferentFirst = maps:from_list([{K, if K == 1 -> 0; true -> K end}
                                          || K <- lists:seq(1, 10)]),
    NestedKey = #{#{1 => 1} => 0},
    NestedKeyEqual = #{#{1 => 1} => 0},
    NestedKeyDifferent = #{#{1 => 2} => 0},
    Hamt40 = maps:from_list([{K, K} || K <- lists:seq(1, 40)]),
    Hamt40Equal = maps:from_list([{K, K} || K <- lists:seq(1, 40)]),
    Hamt40Different = maps:from_list([{K, if K == 40 -> 0; true -> K end}
                                      || K <- lists:seq(1, 40)]),
    lists:foreach(fun(Name) ->
        run_case(Name, List, ListEqual, ListDifferent, Tuple, TupleEqual, TupleDifferent,
                 Deep, DeepEqual, DeepDifferent, Map, MapEqual, MapDifferent,
                 NestedKey, NestedKeyEqual, NestedKeyDifferent,
                 Hamt40, Hamt40Equal, Hamt40Different,
                 SmallAtom, SmallAtomOther, Tuple10Atoms, Tuple10AtomsDifferent,
                 List100, List100DifferentFirst, Map10, Map10DifferentFirst)
    end, Names),
    halt().
run_case(Name, List, ListEqual, ListDifferent, Tuple, TupleEqual, TupleDifferent,
         Deep, DeepEqual, DeepDifferent, Map, MapEqual, MapDifferent,
         NestedKey, NestedKeyEqual, NestedKeyDifferent,
         Hamt40, Hamt40Equal, Hamt40Different,
         SmallAtom, SmallAtomOther, Tuple10Atoms, Tuple10AtomsDifferent,
         List100, List100DifferentFirst, Map10, Map10DifferentFirst) ->
    {EqualLeft, EqualRight, CompareLeft, CompareRight} = case Name of
        "list" -> {List, ListEqual, List, ListDifferent};
        "tuple" -> {Tuple, TupleEqual, Tuple, TupleDifferent};
        "nested" -> {Deep, DeepEqual, Deep, DeepDifferent};
        "map" -> {Map, MapEqual, Map, MapDifferent};
        "nested_key" -> {NestedKey, NestedKeyEqual, NestedKey, NestedKeyDifferent};
        "hamt40" -> {Hamt40, Hamt40Equal, Hamt40, Hamt40Different};
        "small_atoms" -> {SmallAtom, SmallAtom, SmallAtom, SmallAtomOther};
        "tuple10_atoms" -> {Tuple10Atoms, Tuple10Atoms, Tuple10Atoms, Tuple10AtomsDifferent};
        "list100" -> {List100, List100, List100, List100DifferentFirst};
        "map10" -> {Map10, Map10, Map10, Map10DifferentFirst};
        "unequal_first" -> {List100, List100, List100, List100DifferentFirst}
    end,
    N = 10000000,
    Base0 = erlang:monotonic_time(nanosecond),
    _ = empty_even(N, EqualLeft, EqualRight, 0),
    EmptyTime = erlang:monotonic_time(nanosecond) - Base0,
    Eq0 = erlang:monotonic_time(nanosecond),
    _ = eq_even(N, EqualLeft, EqualRight, 0),
    EqTime = (erlang:monotonic_time(nanosecond) - Eq0 - EmptyTime) / N,
    Loose0 = erlang:monotonic_time(nanosecond),
    _ = loose_even(N, EqualLeft, EqualRight, 0),
    LooseTime = (erlang:monotonic_time(nanosecond) - Loose0 - EmptyTime) / N,
    Cmp0 = erlang:monotonic_time(nanosecond),
    _ = cmp_even(N, CompareLeft, CompareRight, 0),
    CmpTime = (erlang:monotonic_time(nanosecond) - Cmp0 - EmptyTime) / N,
    io:format("~s ~.2f ~.2f ~.2f~n", [Name, EqTime, LooseTime, CmpTime]).
empty_even(0, _, _, Acc) -> Acc;
empty_even(N, A, B, Acc) -> empty_odd(N - 1, A, B, Acc + 1).
empty_odd(0, _, _, Acc) -> Acc;
empty_odd(N, A, B, Acc) -> empty_even(N - 1, A, B, Acc + 1).
eq_even(0, _, _, Acc) -> Acc;
eq_even(N, A, B, Acc) ->
    V = if A =:= B -> 1; true -> 0 end,
    eq_odd(N - 1, A, B, Acc + V).
eq_odd(0, _, _, Acc) -> Acc;
eq_odd(N, A, B, Acc) ->
    V = if B =:= A -> 1; true -> 0 end,
    eq_even(N - 1, A, B, Acc + V).
loose_even(0, _, _, Acc) -> Acc;
loose_even(N, A, B, Acc) ->
    V = if A == B -> 1; true -> 0 end,
    loose_odd(N - 1, A, B, Acc + V).
loose_odd(0, _, _, Acc) -> Acc;
loose_odd(N, A, B, Acc) ->
    V = if B == A -> 1; true -> 0 end,
    loose_even(N - 1, A, B, Acc + V).
cmp_even(0, _, _, Acc) -> Acc;
cmp_even(N, A, B, Acc) ->
    Order = erts_internal:cmp_term(A, B),
    V = if Order < 0 -> -1; Order > 0 -> 1; true -> 0 end,
    cmp_odd(N - 1, A, B, Acc + V).
cmp_odd(0, _, _, Acc) -> Acc;
cmp_odd(N, A, B, Acc) ->
    Order = erts_internal:cmp_term(B, A),
    V = if Order < 0 -> -1; Order > 0 -> 1; true -> 0 end,
    cmp_even(N - 1, A, B, Acc + V).
    "#;

    let reference_dir = std::env::temp_dir().join(format!("eq-stack-bench-{}", std::process::id()));
    std::fs::create_dir_all(&reference_dir).unwrap();
    let reference_source = reference_dir.join("eq_stack_bench.erl");
    std::fs::write(&reference_source, reference_module).unwrap();
    let compile = std::process::Command::new("erlc")
        .arg("-o")
        .arg(&reference_dir)
        .arg(&reference_source)
        .output()
        .expect("OTP 29.1.1 erlc is required for the differential benchmark");
    assert!(
        compile.status.success(),
        "{}",
        String::from_utf8_lossy(&compile.stderr)
    );

    fn reference_round(
        directory: &std::path::Path,
        cases: &[Case],
    ) -> Vec<(String, f64, f64, f64)> {
        let names = cases
            .iter()
            .map(|case| format!("\"{}\"", case.name))
            .collect::<Vec<_>>()
            .join(",");
        let expression = format!("eq_stack_bench:run([{names}]).");
        let output = std::process::Command::new("erl")
            .args(["-noshell", "-pa"])
            .arg(directory)
            .args(["-eval", &expression])
            .output()
            .expect("OTP 29.1.1 erl is required for the differential benchmark");
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(|line| {
                let mut fields = line.split_whitespace();
                (
                    fields.next().unwrap().to_owned(),
                    fields.next().unwrap().parse().unwrap(),
                    fields.next().unwrap().parse().unwrap(),
                    fields.next().unwrap().parse().unwrap(),
                )
            })
            .collect()
    }

    fn median(values: &mut [f64]) -> f64 {
        values.sort_by(f64::total_cmp);
        values[values.len() / 2]
    }

    let mut rust_samples = vec![vec![(0.0, 0.0, 0.0); cases.len()]; ROUNDS];
    let mut reference_samples = vec![vec![(String::new(), 0.0, 0.0, 0.0); cases.len()]; ROUNDS];
    for round in 0..ROUNDS {
        if round & 1 == 0 {
            reference_samples[round] = reference_round(&reference_dir, &cases);
            rust_samples[round] = rust_round(&cases);
        } else {
            rust_samples[round] = rust_round(&cases);
            reference_samples[round] = reference_round(&reference_dir, &cases);
        }
    }
    for (index, case) in cases.iter().enumerate() {
        let mut otp_eq: Vec<_> = reference_samples
            .iter()
            .map(|sample| sample[index].1)
            .collect();
        let mut rust_eq: Vec<_> = rust_samples.iter().map(|sample| sample[index].0).collect();
        let mut otp_loose: Vec<_> = reference_samples
            .iter()
            .map(|sample| sample[index].2)
            .collect();
        let mut rust_loose: Vec<_> = rust_samples.iter().map(|sample| sample[index].1).collect();
        let mut otp_cmp: Vec<_> = reference_samples
            .iter()
            .map(|sample| sample[index].3)
            .collect();
        let mut rust_cmp: Vec<_> = rust_samples.iter().map(|sample| sample[index].2).collect();
        eprintln!(
            "{} =:= OTP {:.2} [{:.2}–{:.2}] ns, Arinsal {:.2} [{:.2}–{:.2}] ns; == OTP {:.2} [{:.2}–{:.2}] ns, Arinsal {:.2} [{:.2}–{:.2}] ns; cmp (<) OTP {:.2} [{:.2}–{:.2}] ns, Arinsal {:.2} [{:.2}–{:.2}] ns",
            case.name,
            median(&mut otp_eq),
            otp_eq.iter().copied().fold(f64::INFINITY, f64::min),
            otp_eq.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            median(&mut rust_eq),
            rust_eq.iter().copied().fold(f64::INFINITY, f64::min),
            rust_eq.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            median(&mut otp_loose),
            otp_loose.iter().copied().fold(f64::INFINITY, f64::min),
            otp_loose.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            median(&mut rust_loose),
            rust_loose.iter().copied().fold(f64::INFINITY, f64::min),
            rust_loose.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            median(&mut otp_cmp),
            otp_cmp.iter().copied().fold(f64::INFINITY, f64::min),
            otp_cmp.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            median(&mut rust_cmp),
            rust_cmp.iter().copied().fold(f64::INFINITY, f64::min),
            rust_cmp.iter().copied().fold(f64::NEG_INFINITY, f64::max),
        );
    }
}
