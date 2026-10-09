//! Differential tests of `maps:merge/2`, `maps:from_list/1` and `maps:from_keys/2`
//! against `erl`: iteration order, flat size and structural sharing
//! (`erts_debug:size/1` of the inputs and the result together).

use arinsal_maps::{MapError, MergeStart, from_keys, from_list, hashmap_merge, merge, merge_start};
use arinsal_term::{ProcessHeap, Term, VecHeap};
use std::collections::HashSet;
use std::process::Command;

fn small(n: i64) -> Term {
    Term::small(n).unwrap()
}

fn erl_lines(eval: &str) -> Option<Vec<String>> {
    let output = match Command::new("erl")
        .args(["-noshell", "-eval", eval])
        .output()
    {
        Ok(output) => output,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            eprintln!("skipping differential test: erl not found");
            return None;
        }
        Err(e) => panic!("erl failed: {e}"),
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Some(
        String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect(),
    )
}

/// `len` heap words at a pointer term's address.
fn object_words(term: Term, len: usize) -> &'static [u64] {
    // SAFETY: test terms live in a heap that outlives every check, and `len`
    // never exceeds the object at that address.
    unsafe { std::slice::from_raw_parts(term.raw_ptr(), len) }
}

/// `erts_debug:size/1` of integer-keyed, integer-valued maps: heap words of
/// the maps, shared subterms counted once.
fn shared_size(roots: &[Term], seen: &mut HashSet<usize>) -> usize {
    let mut words = 0;
    let mut stack: Vec<Term> = roots.to_vec();
    while let Some(term) = stack.pop() {
        if !term.is_pointer() {
            continue;
        }
        let Some(header) = term.header() else {
            // A leaf cons of two small integers.
            if seen.insert(object_words(term, 2).as_ptr() as usize) {
                words += 2;
            }
            continue;
        };
        let len = match header & 63 {
            0x2c => match (header >> 6) & 3 {
                0 => 3 + object_words(term, 2)[1] as usize,
                1 => 1 + ((header >> 16) as u16).count_ones() as usize,
                2 => 18,
                _ => 2 + ((header >> 16) as u16).count_ones() as usize,
            },
            _ => 1 + (header >> 6) as usize,
        };
        // The static empty key tuple is a literal, as in erts.
        if header == 0 || !seen.insert(object_words(term, len).as_ptr() as usize) {
            continue;
        }
        words += len;
        if term.is_hashmap() || header & 63 == 0 {
            stack.extend(arinsal_term::hashmap_node_children(term).unwrap());
        } else if header & 63 == 0x2c {
            stack.push(term.flatmap_keys_tuple().unwrap());
        }
    }
    words
}

fn int_map(heap: &mut VecHeap, keys: impl Iterator<Item = i64>, value_offset: i64) -> Term {
    let pairs: Vec<_> = keys.map(|k| (small(k), small(k + value_offset))).collect();
    from_list(&pairs, heap).unwrap()
}

fn keys_line(map: Term) -> String {
    arinsal_maps::to_list(map)
        .unwrap()
        .iter()
        .map(|(k, v)| format!("{}:{}", k.as_small().unwrap(), v.as_small().unwrap()))
        .collect::<Vec<_>>()
        .join(" ")
}

const CASES: &[(i64, i64, i64)] = &[
    (0, 0, 0),
    (0, 5, 0),
    (5, 0, 0),
    (5, 5, 0),
    (20, 20, 10),
    (32, 32, 0),
    (32, 32, 16),
    (16, 17, 16),
    (33, 32, 0),
    (32, 33, 0),
    (40, 3, 1),
    (3, 40, 1),
    (100, 100, 50),
    (100, 100, 0),
    (1000, 1000, 500),
    (1000, 10, 995),
    (10, 1000, 3),
    (3000, 3000, 2999),
    (3000, 3000, 100000),
];

#[test]
fn differential_merge_order_and_sharing() {
    let eval = format!(
        "lists:foreach(fun({{A,B,Off}}) -> \
           L = maps:from_list([{{K,K}} || K <- lists:seq(1,A)]), \
           R = maps:from_list([{{K+Off,K+Off+1000000}} || K <- lists:seq(1,B)]), \
           M = maps:merge(L, R), \
           io:format(\"~s~n~B ~B~n\", [lists:join(\" \", [io_lib:format(\"~B:~B\", [K,V]) || {{K,V}} <- maps:to_list(M)]), \
             erts_debug:flat_size(M), erts_debug:size({{L,R,M}}) - 4]) end, {}), halt().",
        erl_cases()
    );
    let Some(lines) = erl_lines(&eval) else {
        return;
    };
    let mut heap = VecHeap::new();
    for (index, &(a, b, off)) in CASES.iter().enumerate() {
        let left = int_map(&mut heap, 1..=a, 0);
        let right = int_map(&mut heap, (1..=b).map(|k| k + off), 1_000_000);
        let merged = merge(left, right, &mut heap).unwrap();
        assert_eq!(keys_line(merged), lines[2 * index], "order {a} {b} {off}");
        let flat = shared_size(&[merged], &mut HashSet::new());
        let shared = shared_size(&[left, right, merged], &mut HashSet::new());
        assert_eq!(
            format!("{flat} {shared}"),
            lines[2 * index + 1],
            "sizes {a} {b} {off}"
        );
    }
}

fn erl_cases() -> String {
    let cases: Vec<_> = CASES
        .iter()
        .map(|(a, b, off)| format!("{{{a},{b},{off}}}"))
        .collect();
    format!("[{}]", cases.join(","))
}

#[test]
fn yielding_merge_matches_unbounded_merge() {
    let mut heap = VecHeap::new();
    let left = int_map(&mut heap, 1..=5000, 0);
    let right = int_map(&mut heap, 2500..=7500, 7);
    let expected = keys_line(merge(left, right, &mut heap).unwrap());
    let MergeStart::Hashmap(mut ctx) = merge_start(left, right, &mut heap).unwrap() else {
        panic!("two HAMTs merge structurally");
    };
    let mut yields = 0;
    let merged = loop {
        let mut reds = 50;
        if let Some(map) = hashmap_merge(&mut ctx, &mut reds, &mut heap).unwrap() {
            break map;
        }
        yields += 1;
    };
    assert!(yields > 10, "{yields}");
    assert_eq!(keys_line(merged), expected);
}

type Attempt<'a> = dyn Fn(&mut ProcessHeap) -> Result<Term, MapError> + 'a;

#[test]
fn heap_full_reports_the_whole_construction() {
    let mut heap = VecHeap::new();
    let left = int_map(&mut heap, 1..=200, 0);
    let right = int_map(&mut heap, 150..=400, 3);
    let flat_left = int_map(&mut heap, 1..=20, 0);
    let pairs: Vec<_> = (1..=300).map(|k| (small(k % 250), small(k))).collect();
    let keys: Vec<_> = (1..=300).map(small).collect();
    let attempts: [&Attempt<'_>; 4] = [
        &|h| merge(left, right, h),
        &|h| merge(flat_left, right, h),
        &|h| from_list(&pairs, h),
        &|h| from_keys(&keys, small(0), h),
    ];
    for attempt in attempts {
        let mut tiny = ProcessHeap::with_words(16);
        let Err(MapError::HeapFull { need_words }) = attempt(&mut tiny) else {
            panic!("tiny heap must overflow");
        };
        let mut exact = ProcessHeap::with_words(need_words);
        let map = attempt(&mut exact).unwrap();
        assert_eq!(exact.used_words(), need_words);
        let mut roomy = ProcessHeap::with_words(1 << 16);
        assert_eq!(keys_line(map), keys_line(attempt(&mut roomy).unwrap()));
    }
}

#[test]
fn differential_from_list_and_from_keys() {
    let cases: &[(i64, i64)] = &[
        (0, 1),
        (1, 1),
        (10, 3),
        (32, 1000),
        (33, 1000),
        (40, 32),
        (40, 33),
        (100, 7),
        (1000, 1000),
        (1000, 999),
    ];
    let list: Vec<_> = cases.iter().map(|(n, d)| format!("{{{n},{d}}}")).collect();
    let eval = format!(
        "lists:foreach(fun({{N,D}}) -> \
           M = maps:from_list([{{K rem D, K}} || K <- lists:seq(1,N)]), \
           F = maps:from_keys([K rem D || K <- lists:seq(1,N)], 7), \
           P = fun(X) -> lists:join(\" \", [io_lib:format(\"~B:~B\", [K,V]) || {{K,V}} <- maps:to_list(X)]) end, \
           io:format(\"~s~n~s~n~B ~B~n\", [P(M), P(F), erts_debug:flat_size(M), erts_debug:flat_size(F)]) end, [{}]), halt().",
        list.join(",")
    );
    let Some(lines) = erl_lines(&eval) else {
        return;
    };
    let mut heap = VecHeap::new();
    for (index, &(n, d)) in cases.iter().enumerate() {
        let pairs: Vec<_> = (1..=n).map(|k| (small(k % d), small(k))).collect();
        let keys: Vec<_> = (1..=n).map(|k| small(k % d)).collect();
        let m = from_list(&pairs, &mut heap).unwrap();
        let f = from_keys(&keys, small(7), &mut heap).unwrap();
        assert_eq!(keys_line(m), lines[3 * index], "from_list {n} {d}");
        assert_eq!(keys_line(f), lines[3 * index + 1], "from_keys {n} {d}");
        let sizes = format!(
            "{} {}",
            shared_size(&[m], &mut HashSet::new()),
            shared_size(&[f], &mut HashSet::new())
        );
        assert_eq!(sizes, lines[3 * index + 2], "sizes {n} {d}");
    }
}
