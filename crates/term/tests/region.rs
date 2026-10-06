use arinsal_etf::{EncodeOptions, OwnedTerm, decode, encode};
#[cfg(not(miri))]
use arinsal_term::phash2;
use arinsal_term::{
    BuiltList, GrowingList, RegionBuilder, RegionRoots, Term, TermBuilder, TermError, VecHeap, cmp,
    exact_eq, from_owned, is_region_term, make_hash2, region_owner, seal_for_send, to_owned,
};
use std::cmp::Ordering;
#[cfg(not(miri))]
use std::io::Write;
#[cfg(not(miri))]
use std::process::Command;
use std::time::{Duration, Instant};

fn small(value: i64) -> Term {
    Term::small(value).unwrap()
}

#[test]
fn lifetime_nested_regions_and_interior_resend() {
    let mut list_builder = RegionBuilder::new();
    let mut list = Term::NIL;
    for i in 0..12_000 {
        list = list_builder.cons(small(i % 53), list).unwrap();
    }
    // SAFETY: list_root is still builder-owned and no region cells have moved.
    let interior = unsafe { list.cons_ref() }.unwrap().1;
    let list_root = list_builder.seal(list).unwrap();
    assert!(is_region_term(interior));
    assert_eq!(interior.classify(), arinsal_term::TermKind::List);
    let mut outer_builder = RegionBuilder::new();
    let outer = outer_builder.tuple(&[small(9), interior]).unwrap();
    let outer_root = outer_builder.seal(outer).unwrap();
    drop(list_root);
    let mut receiver = RegionRoots::new();
    assert_eq!(receiver.adopt(outer_root.clone()), outer);
    assert_eq!(receiver.virtual_bytes(), (12_000 * 2 + 3) * 8);
    assert!(receiver.collection_due(1, receiver.virtual_bytes()));
    let resent = seal_for_send(interior).unwrap();
    let mut next_receiver = RegionRoots::new();
    assert_eq!(next_receiver.adopt(resent), interior);
    drop(outer_root);
    drop(receiver);
    // SAFETY: next_receiver still retains the region containing interior.
    let head = unsafe { interior.cons_ref() }.unwrap().0;
    assert_eq!(head.as_small(), Some(20));
    next_receiver.begin_gc();
    assert!(next_receiver.mark(interior));
    next_receiver.finish_gc();
    assert_eq!(next_receiver.virtual_bytes(), 12_000 * 2 * 8);
    next_receiver.begin_gc();
    next_receiver.finish_gc();
    assert_eq!(next_receiver.virtual_bytes(), 0);
}

#[test]
fn private_edges_are_rejected_and_fallback_is_bounded() {
    let mut private = VecHeap::new();
    let foreign = TermBuilder::new(&mut private)
        .cons(small(1), Term::NIL)
        .unwrap();
    let mut region = RegionBuilder::new();
    let empty = TermBuilder::new(&mut private).tuple(&[]).unwrap();
    assert!(region.cons(empty, Term::NIL).is_ok());
    assert_eq!(
        region.cons(foreign, Term::NIL).unwrap_err(),
        TermError::BadArg
    );
    assert_eq!(region.tuple(&[foreign]).unwrap_err(), TermError::BadArg);
    let copied = seal_for_send(foreign).unwrap();
    assert!(exact_eq(copied.term(), foreign));
    let mut large = Term::NIL;
    for _ in 0..3000 {
        large = TermBuilder::new(&mut private)
            .cons(small(2), large)
            .unwrap();
    }
    assert_eq!(seal_for_send(large).err(), Some(TermError::SystemLimit));
}

#[test]
fn generic_owned_constructor_and_term_views() {
    let value = OwnedTerm::Tuple(vec![
        OwnedTerm::List {
            elems: vec![
                OwnedTerm::Int(1),
                OwnedTerm::Float(2.5),
                OwnedTerm::Binary(vec![7; 70]),
            ],
            tail: Box::new(OwnedTerm::Nil),
        },
        OwnedTerm::Map(vec![
            (OwnedTerm::Atom("a".into()), OwnedTerm::Int(-37)),
            (OwnedTerm::Atom("b".into()), OwnedTerm::Binary(vec![3; 12])),
        ]),
    ]);
    let mut region = RegionBuilder::new();
    let root = region.from_owned(&value).unwrap();
    let root = region.seal(root).unwrap();
    let mut private = VecHeap::new();
    let ordinary = from_owned(&value, &mut private).unwrap();
    assert!(exact_eq(root.term(), ordinary));
    assert_eq!(cmp(root.term(), ordinary), Ordering::Equal);
    assert_eq!(make_hash2(root.term()), make_hash2(ordinary));
    let encoded = encode(&to_owned(root.term()).unwrap(), EncodeOptions::default());
    assert_eq!(decode(&encoded).unwrap(), to_owned(ordinary).unwrap());
    assert!(region_owner(root.term()).is_some());
}

#[test]
#[cfg(not(miri))]
fn differential_random_corpus_against_erts() {
    if Command::new("erl").arg("-version").output().is_err() {
        eprintln!("skip region differential: erl is unavailable");
        return;
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = || {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed
    };
    let mut corpus = Vec::new();
    for _ in 0..64 {
        let n = next() as i64 % 100_000;
        let width = (next() % 8 + 1) as usize;
        let items: Vec<_> = (0..width)
            .map(|_| OwnedTerm::Int(next() as i64 % 1000))
            .collect();
        let list = OwnedTerm::List {
            elems: items,
            tail: Box::new(OwnedTerm::Nil),
        };
        corpus.push(OwnedTerm::Tuple(vec![
            OwnedTerm::Int(n),
            list,
            OwnedTerm::Map(vec![
                (
                    OwnedTerm::Atom("a".into()),
                    OwnedTerm::Binary(vec![(next() & 255) as u8; width]),
                ),
                (OwnedTerm::Atom("b".into()), OwnedTerm::Int(n / 7)),
            ]),
        ]));
    }
    let mut region = RegionBuilder::new();
    let mut private = VecHeap::new();
    let mut hashes = Vec::new();
    let mut terms = Vec::new();
    let mut last = None;
    let mut etf = Vec::new();
    for value in &corpus {
        let term = region.from_owned(value).unwrap();
        last = Some(term);
        terms.push(term);
        let ordinary = from_owned(value, &mut private).unwrap();
        assert!(exact_eq(term, ordinary));
        assert_eq!(cmp(term, ordinary), Ordering::Equal);
        assert_eq!(make_hash2(term), make_hash2(ordinary));
        hashes.push(phash2(term));
        let bytes = encode(&to_owned(term).unwrap(), EncodeOptions::default());
        etf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        etf.extend_from_slice(&bytes);
    }
    let published = region.seal(last.unwrap()).unwrap();
    assert!(region_owner(published.term()).is_some());
    let path = std::env::temp_dir().join(format!(
        "arinsal-region-{}-{}.etf",
        std::process::id(),
        next()
    ));
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(&etf).unwrap();
    drop(file);
    let output = Command::new("erl")
        .args(["-noshell", "-eval", "{ok,B}=file:read_file(os:getenv(\"ARINSAL_REGION_ETF\")), F=fun F(<<>>,A)->lists:reverse(A); F(<<N:32/unsigned-big,V:N/binary,R/binary>>,A)->T=binary_to_term(V), F(R,[{erlang:phash2(T),term_to_binary(T)}|A]) end, lists:foreach(fun({H,V})->Hex=lists:flatten([io_lib:format(\"~2.16.0B\",[X]) || X <- binary_to_list(V)]),io:format(\"~B ~s~n\",[H,Hex]) end,F(B,[])), halt()."])
        .env("ARINSAL_REGION_ETF", &path)
        .output().unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8(output.stdout).unwrap();
    let lines: Vec<_> = output.lines().collect();
    assert_eq!(lines.len(), corpus.len());
    for (i, line) in lines.iter().enumerate() {
        let (hash, hex) = line.split_once(' ').unwrap();
        assert_eq!(hash.parse::<u32>().unwrap(), hashes[i], "case {i}");
        let bytes: Vec<u8> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect();
        let from_erts = decode(&bytes).unwrap();
        let mut heap = VecHeap::new();
        let roundtrip = from_owned(&from_erts, &mut heap).unwrap();
        assert!(exact_eq(terms[i], roundtrip), "ETF case {i}");
    }
}

#[test]
fn overlapping_dag_accounting_and_gc_release() {
    let mut child_builder = RegionBuilder::new();
    let child = child_builder.cons(small(3), Term::NIL).unwrap();
    let child_root = child_builder.seal(child).unwrap();
    let mut left_builder = RegionBuilder::new();
    let left = left_builder.tuple(&[child]).unwrap();
    let left_root = left_builder.seal(left).unwrap();
    let mut right_builder = RegionBuilder::new();
    let right = right_builder.tuple(&[child, small(5)]).unwrap();
    let right_root = right_builder.seal(right).unwrap();
    drop(child_root);
    let mut receiver = RegionRoots::new();
    receiver.adopt(left_root);
    assert_eq!(receiver.virtual_bytes(), (2 + 2) * 8);
    receiver.adopt(right_root);
    assert_eq!(receiver.virtual_bytes(), (2 + 2 + 3) * 8);
    receiver.begin_gc();
    assert!(receiver.mark(right));
    receiver.finish_gc();
    assert_eq!(receiver.virtual_bytes(), (2 + 3) * 8);
    receiver.begin_gc();
    receiver.finish_gc();
    assert_eq!(receiver.virtual_bytes(), 0);
}

#[test]
fn growing_list_places_large_closed_spine_in_region() {
    let mut private = VecHeap::new();
    let mut short = GrowingList::with_threshold_cons(8);
    for i in 0..8 {
        short.prepend(small(i)).unwrap();
    }
    assert!(matches!(
        short.finish(&mut private).unwrap(),
        BuiltList::Private(_)
    ));
    let mut long = GrowingList::with_threshold_cons(8);
    for i in 0..24 {
        long.prepend(small(i)).unwrap();
    }
    let BuiltList::Shared(root) = long.finish(&mut private).unwrap() else {
        panic!("expected region");
    };
    assert_eq!(root.region_bytes(), 24 * 2 * 8);
    assert!(is_region_term(root.term()));
    let mut ordinary = Term::NIL;
    for i in 0..24 {
        ordinary = TermBuilder::new(&mut private)
            .cons(small(i), ordinary)
            .unwrap();
    }
    assert!(exact_eq(root.term(), ordinary));
}

#[test]
fn release_latency_gate() {
    if cfg!(debug_assertions) {
        return;
    }
    let mut direct = RegionBuilder::new();
    let mut direct_list = Term::NIL;
    for i in 0..65_536 {
        direct_list = direct
            .cons(small((i * 31 % 1009) as i64), direct_list)
            .unwrap();
    }
    let direct_wrapper = direct.tuple(&[small(7), direct_list]).unwrap();
    let mut direct_receiver = RegionRoots::new();
    let start = Instant::now();
    let direct_root = direct.seal(direct_wrapper).unwrap();
    std::hint::black_box(direct_receiver.adopt(seal_for_send(direct_root.term()).unwrap()));
    let direct_elapsed = start.elapsed();
    assert_eq!(
        direct_receiver.virtual_bytes(),
        direct_root.retained_bytes()
    );
    let mut growing = GrowingList::new();
    for i in 0..65_536 {
        growing.prepend(small(i % 97)).unwrap();
    }
    let mut private = VecHeap::new();
    let BuiltList::Shared(list) = growing.finish(&mut private).unwrap() else {
        panic!("expected region");
    };
    let mut wrapper = RegionBuilder::new();
    let wrapped = wrapper.tuple(&[small(42), list.term()]).unwrap();
    let source = wrapper.seal(wrapped).unwrap();
    let mut first = RegionRoots::new();
    let start = Instant::now();
    std::hint::black_box(first.adopt(seal_for_send(std::hint::black_box(source.term())).unwrap()));
    let first_elapsed = start.elapsed();
    assert_eq!(first.virtual_bytes(), source.retained_bytes());
    let mut repeated = RegionRoots::new();
    let start = Instant::now();
    std::hint::black_box(
        repeated.adopt(seal_for_send(std::hint::black_box(source.term())).unwrap()),
    );
    let repeated_elapsed = start.elapsed();
    assert_eq!(repeated.virtual_bytes(), source.retained_bytes());
    let mut recipients: Vec<_> = (0..1000).map(|_| RegionRoots::new()).collect();
    let start = Instant::now();
    for recipient in &mut recipients {
        std::hint::black_box(recipient.adopt(source.clone()));
    }
    let fanout_elapsed = start.elapsed();
    assert_eq!(
        recipients
            .iter()
            .map(RegionRoots::virtual_bytes)
            .sum::<usize>(),
        1000 * source.retained_bytes()
    );
    eprintln!(
        "region latency: publish={direct_elapsed:?} first={first_elapsed:?} repeated={repeated_elapsed:?} fanout1000={fanout_elapsed:?}"
    );
    assert!(direct_elapsed < Duration::from_micros(100));
    assert!(first_elapsed < Duration::from_micros(100));
    assert!(repeated_elapsed < Duration::from_micros(100));
    assert!(fanout_elapsed < Duration::from_micros(50));
}
