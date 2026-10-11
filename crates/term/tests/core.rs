use arinsal_etf::OwnedTerm;
use arinsal_term::{
    AtomTable, MAX_SMALL, MIN_SMALL, ProcessHeap, Term, TermBuilder, VecHeap, cmp, copy_term,
    exact_eq, from_owned, loose_eq, make_hash2, phash2, size_object, small_add, small_mul,
    small_sub, to_owned,
};
#[cfg(not(miri))]
use arinsal_term::{internal_hash, make_hash, phash, phash2_range};
use similar_asserts::assert_eq;
use std::cmp::Ordering;
#[cfg(not(miri))]
use std::process::Command;
use std::sync::Arc;

#[test]
fn tag_roundtrips_and_heap_layouts() {
    assert_eq!(std::mem::size_of::<Term>(), 8);
    for n in [MIN_SMALL, MIN_SMALL + 1, -1, 0, 1, MAX_SMALL - 1, MAX_SMALL] {
        assert_eq!(Term::small(n).unwrap().as_small(), Some(n));
    }
    assert!(Term::small(MIN_SMALL - 1).is_none());
    assert!(Term::small(MAX_SMALL + 1).is_none());
    assert_eq!(
        Term::pid((1 << 28) - 1, u32::MAX).unwrap().as_pid(),
        Some(((1 << 28) - 1, u32::MAX))
    );
    // SAFETY: nil is an immediate with no heap address.
    assert_eq!(unsafe { Term::NIL.raw_bits() }, 0x3b);
    let mut heap = VecHeap::new();
    let mut b = TermBuilder::new(&mut heap);
    let float = b.float(-0.0).unwrap();
    assert_eq!(float.header(), Some((1 << 6) | 0x18));
    assert_eq!(size_object(b.tuple(&[]).unwrap()), 0);
    let big = b.int_from_i128(1 << 70).unwrap();
    assert_eq!(big.header().unwrap() & 63, 0x08);
    let heap_binary = b.binary(&[1; 64]).unwrap();
    assert_eq!(heap_binary.header().unwrap() & 63, 0x20);
    let off_heap = b.binary(&[1; 65]).unwrap();
    assert_eq!(off_heap.header().unwrap() & 63, 0x24);
    assert_eq!(size_object(off_heap), 8);
    let tuple = b.tuple(&[Term::small(1).unwrap(), big]).unwrap();
    assert_eq!(size_object(tuple), 3 + 3);
}

#[test]
fn flatmap_update_reuses_keys_and_allocates_header_and_values_only() {
    let keys = [
        Term::small(2).unwrap(),
        Term::small(5).unwrap(),
        Term::small(9).unwrap(),
    ];
    let mut key_heap = VecHeap::new();
    let key_tuple = TermBuilder::new(&mut key_heap).tuple(&keys).unwrap();

    let mut heap = VecHeap::new();
    let values = [
        Term::small(20).unwrap(),
        Term::small(50).unwrap(),
        Term::small(90).unwrap(),
    ];
    let map = TermBuilder::new(&mut heap)
        .flatmap_with_key_tuple(key_tuple, &values)
        .unwrap();

    // Port of erts/emulator/beam/beam_common.c:2260-2274, OTP-29.1.1.
    assert_eq!(heap.used_words(), 3 + values.len());
    assert_eq!(map.flatmap_keys_tuple(), Some(key_tuple));
}

#[test]
fn process_heap_and_fragment() {
    let mut heap = ProcessHeap::with_words(8);
    assert!(heap.reserve_stack(2));
    assert!(heap.alloc(6).is_some());
    assert!(heap.alloc(1).is_none());
    assert!(!heap.heap_fragment(100).is_null());
}

#[test]
fn copy_and_owned_roundtrip() {
    let original = OwnedTerm::Tuple(vec![
        OwnedTerm::List {
            elems: vec![OwnedTerm::Int(1), OwnedTerm::Atom("ok".into())],
            tail: Box::new(OwnedTerm::Nil),
        },
        OwnedTerm::Map(vec![
            (OwnedTerm::Atom("b".into()), OwnedTerm::Binary(vec![7; 65])),
            (OwnedTerm::Atom("a".into()), OwnedTerm::Float(-0.0)),
        ]),
    ]);
    let mut src = VecHeap::new();
    let term = from_owned(&original, &mut src).unwrap();
    let mut dst = VecHeap::new();
    let copy = copy_term(term, &mut dst).unwrap();
    assert!(exact_eq(term, copy));
    assert_eq!(size_object(term), dst.used_words());
    let owned = to_owned(copy).unwrap();
    if let OwnedTerm::Tuple(values) = &owned {
        assert_eq!(values.len(), 2);
    } else {
        panic!("not tuple");
    }
}

#[test]
fn number_equality_and_order() {
    let mut heap = VecHeap::new();
    let mut b = TermBuilder::new(&mut heap);
    let zero = b.float(0.0).unwrap();
    let neg_zero = b.float(-0.0).unwrap();
    let int_zero = Term::small(0).unwrap();
    assert!(loose_eq(zero, neg_zero));
    assert!(!exact_eq(zero, neg_zero));
    assert!(loose_eq(int_zero, zero));
    assert!(!exact_eq(int_zero, zero));
    assert_eq!(cmp(int_zero, zero), Ordering::Equal);
    let big = b.int_from_i128((1_i128 << 60) + 1).unwrap();
    let rounded = b.float(((1_i128 << 60) + 1) as f64).unwrap();
    assert_eq!(cmp(big, rounded), Ordering::Greater);
    assert_eq!(
        small_add(Term::small(2).unwrap(), Term::small(3).unwrap())
            .unwrap()
            .as_small(),
        Some(5)
    );
    assert!(small_add(Term::small(MAX_SMALL).unwrap(), Term::small(1).unwrap()).is_none());
    assert_eq!(
        small_sub(Term::small(2).unwrap(), Term::small(3).unwrap())
            .unwrap()
            .as_small(),
        Some(-1)
    );
    assert_eq!(
        small_mul(Term::small(2).unwrap(), Term::small(3).unwrap())
            .unwrap()
            .as_small(),
        Some(6)
    );
}

#[test]
fn small_arithmetic_boundaries_and_random_pairs() {
    let values = [
        MIN_SMALL,
        MIN_SMALL + 1,
        -(1 << 28),
        -1,
        0,
        1,
        1 << 28,
        MAX_SMALL - 1,
        MAX_SMALL,
    ];
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for i in 0..100_000 {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let a = if i < values.len() * values.len() {
            values[i / values.len()]
        } else {
            ((state as i64) >> 5).clamp(MIN_SMALL, MAX_SMALL)
        };
        let b = if i < values.len() * values.len() {
            values[i % values.len()]
        } else {
            ((state.rotate_left(29) as i64) >> 5).clamp(MIN_SMALL, MAX_SMALL)
        };
        let (a_term, b_term) = (Term::small(a).unwrap(), Term::small(b).unwrap());
        let expected = |n: i128| {
            (MIN_SMALL as i128..=MAX_SMALL as i128)
                .contains(&n)
                .then_some(n as i64)
        };
        assert_eq!(
            small_add(a_term, b_term).and_then(Term::as_small),
            expected(a as i128 + b as i128)
        );
        assert_eq!(
            small_sub(a_term, b_term).and_then(Term::as_small),
            expected(a as i128 - b as i128)
        );
    }
}

#[test]
fn atoms_concurrent_and_limit() {
    let table = Arc::new(AtomTable::new(1_048_576));
    let per_thread = if cfg!(miri) { 10 } else { 62_500 };
    std::thread::scope(|scope| {
        for thread in 0..16 {
            let table = table.clone();
            scope.spawn(move || {
                for n in 0..per_thread {
                    let name = format!("s1_atom_{thread}_{n}");
                    let a = table.intern(&name).unwrap();
                    assert_eq!(table.get(&name), Some(a));
                    assert_eq!(table.text(a), Some(name.as_str()));
                }
            });
        }
    });
    assert_eq!(
        table.len(),
        arinsal_term::atoms::PREDEFINED.len() + 16 * per_thread
    );
    let limited = AtomTable::new(arinsal_term::atoms::PREDEFINED.len());
    assert!(limited.intern("new_atom").is_err());
    assert!(table.intern(&"a".repeat(256)).is_err());
}

#[cfg(not(miri))]
fn erl_values(expr: &str) -> Option<Vec<u32>> {
    let output = Command::new("erl")
        .args(["-noshell", "-eval", expr])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    text.split_whitespace()
        .map(str::parse)
        .collect::<Result<Vec<_>, _>>()
        .ok()
}

#[cfg(not(miri))]
fn erl_values_u64(expr: &str) -> Option<Vec<u64>> {
    let output = Command::new("erl")
        .args(["-noshell", "-eval", expr])
        .output()
        .ok()?;
    assert!(
        output.status.success(),
        "erl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    Some(
        text.lines()
            .filter_map(|line| {
                let numbers = line
                    .split_whitespace()
                    .map(str::parse)
                    .collect::<Result<Vec<u64>, _>>()
                    .ok()?;
                (numbers.len() == 4).then_some(numbers)
            })
            .flatten()
            .collect(),
    )
}

#[test]
#[cfg(not(miri))]
fn differential_hash2_primitives() {
    let expression = "L=[0,1,-1,134217727,134217728,-134217728,abc,ok,[],{},[1,2],<<1,2,3>>,0.0,-0.0,#{a=>1,b=>2}], lists:foreach(fun(T)->io:format(\"~w ~w ~w ~w~n\",[erlang:phash2(T),erlang:phash2(T,1),erlang:phash2(T,134217728),erlang:phash2(T,4294967296)]) end,L), halt().";
    let Some(reference) = erl_values(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    let mut b = TermBuilder::new(&mut heap);
    let small = |n| Term::small(n).unwrap();
    let abc = Term::atom(arinsal_term::global_atoms().intern("abc").unwrap());
    let ok = Term::atom(arinsal_term::atoms::OK);
    let a = Term::atom(arinsal_term::global_atoms().intern("a").unwrap());
    let bb = Term::atom(arinsal_term::global_atoms().intern("b").unwrap());
    let terms = [
        small(0),
        small(1),
        small(-1),
        small(134217727),
        small(134217728),
        small(-134217728),
        abc,
        ok,
        Term::NIL,
        b.tuple(&[]).unwrap(),
        b.list_from_iter([small(1), small(2)]).unwrap(),
        b.binary(&[1, 2, 3]).unwrap(),
        b.float(0.0).unwrap(),
        b.float(-0.0).unwrap(),
        b.flatmap_from_pairs(&[(a, small(1)), (bb, small(2))])
            .unwrap(),
    ];
    assert_eq!(reference.len(), terms.len() * 4);
    for (i, term) in terms.iter().enumerate() {
        assert_eq!(phash2(*term), reference[i * 4], "case {i}");
        assert_eq!(phash2_range(*term, 1), Some(reference[i * 4 + 1]));
        assert_eq!(phash2_range(*term, 1 << 27), Some(reference[i * 4 + 2]));
        assert_eq!(make_hash2(*term), reference[i * 4 + 3], "case {i}");
        assert_eq!(phash2_range(*term, 1_u64 << 32), Some(reference[i * 4 + 3]));
    }
}

#[test]
#[cfg(not(miri))]
fn differential_hash2_improper_byte_list_and_tuple_order() {
    let expression = "T=[97,98|tail],U={1,{2,3},4},io:format(\"~w ~w~n\",[erlang:phash2(T,4294967296),erlang:phash2(U,4294967296)]),halt().";
    let Some(reference) = erl_values(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 2);

    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let small = |value| Term::small(value).unwrap();
    let tail = Term::atom(arinsal_term::global_atoms().intern("tail").unwrap());
    let byte_tail = builder.cons(small(98), tail).unwrap();
    let improper = builder.cons(small(97), byte_tail).unwrap();
    let inner = builder.tuple(&[small(2), small(3)]).unwrap();
    let tuple = builder.tuple(&[small(1), inner, small(4)]).unwrap();

    assert_eq!(make_hash2(improper), reference[0], "improper byte list");
    assert_eq!(make_hash2(tuple), reference[1], "tuple traversal order");
}

#[test]
#[cfg(not(miri))]
fn differential_hash2_binary_tail_bytes() {
    let expression = "lists:foreach(fun(N)->B=list_to_binary(lists:seq(1,N)),io:format(\"~w \",[erlang:phash2(B,4294967296)]) end,[9,10,11,21,22,23]),halt().";
    let Some(reference) = erl_values(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 6);

    let lengths = [9, 10, 11, 21, 22, 23];
    let mut heap = VecHeap::new();
    for (length, expected) in lengths.into_iter().zip(reference) {
        let bytes: Vec<u8> = (1..=length).collect();
        let binary = TermBuilder::new(&mut heap).binary(&bytes).unwrap();
        assert_eq!(make_hash2(binary), expected, "binary length {length}");
    }
}

#[test]
#[ignore = "microbenchmark"]
fn microbenchmark() {
    use std::time::Instant;
    fn measure(name: &str, count: usize, mut operation: impl FnMut()) {
        let start = Instant::now();
        for _ in 0..count {
            operation();
        }
        eprintln!(
            "{name}: {:.1} ns/op",
            start.elapsed().as_nanos() as f64 / count as f64
        );
    }
    let a = Term::small(123).unwrap();
    let b = Term::small(456).unwrap();
    let atom_a = Term::atom(arinsal_term::atoms::OK);
    let atom_b = Term::atom(arinsal_term::atoms::ERROR);
    let mut heap = VecHeap::new();
    let binary = TermBuilder::new(&mut heap).binary(&[17; 1024]).unwrap();
    measure("small_add", 10_000_000, || {
        std::hint::black_box(small_add(std::hint::black_box(a), std::hint::black_box(b)));
    });
    measure("cmp_small", 10_000_000, || {
        std::hint::black_box(cmp(std::hint::black_box(a), std::hint::black_box(b)));
    });
    measure("cmp_atoms", 1_000_000, || {
        std::hint::black_box(cmp(
            std::hint::black_box(atom_a),
            std::hint::black_box(atom_b),
        ));
    });
    measure("tuple_2", 1_000_000, || {
        std::hint::black_box(TermBuilder::new(&mut heap).tuple(&[a, b]).unwrap());
    });
    measure("phash2_1kb", 100_000, || {
        std::hint::black_box(phash2(std::hint::black_box(binary)));
    });
}

#[test]
#[cfg(not(miri))]
fn differential_hash2_ten_thousand_terms() {
    let expression = "erts_debug:set_internal_state(available_internal_state,true), F=fun(N)->case N rem 8 of 0->N-5000; 1->(1 bsl (60+N rem 30))+N; 2->(N-5000)/7; 3-><<(N band 255),((N bsr 3) band 255),((N bsr 8) band 255)>>; 4-><<(N band 31):5>>; 5->{N rem 97,N-5000,ok}; 6->[N band 255,(N bsr 8) band 255,N]; 7->#{(N rem 31)=>N,ok=> -N} end end, lists:foreach(fun(N)->T=F(N),io:format(\"~w ~w ~w ~w~n\",[erlang:phash2(T,4294967296),erts_debug:flat_size(T),erlang:phash(T,4294967296),erts_debug:get_internal_state({internal_hash,T})]) end,lists:seq(0,9999)),halt().";
    let Some(reference) = erl_values_u64(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 40_000);
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let ok = Term::atom(arinsal_term::atoms::OK);
    for n in 0..10_000_i64 {
        let small = |value| Term::small(value).unwrap();
        let term = match n % 8 {
            0 => small(n - 5000),
            1 => builder
                .int_from_i128((1_i128 << (60 + n % 30)) + n as i128)
                .unwrap(),
            2 => builder.float((n - 5000) as f64 / 7.0).unwrap(),
            3 => builder
                .binary(&[n as u8, (n >> 3) as u8, (n >> 8) as u8])
                .unwrap(),
            4 => builder.bitstring(&[((n as u8) & 31) << 3], 5).unwrap(),
            5 => builder
                .tuple(&[small(n % 97), small(n - 5000), ok])
                .unwrap(),
            6 => builder
                .list_from_iter([small(n & 255), small((n >> 8) & 255), small(n)])
                .unwrap(),
            _ => builder
                .flatmap_from_pairs(&[(small(n % 31), small(n)), (ok, small(-n))])
                .unwrap(),
        };
        assert_eq!(
            make_hash2(term) as u64,
            reference[n as usize * 4],
            "hash2 case {n}"
        );
        assert_eq!(
            phash(term, 1_u64 << 32),
            Some(reference[n as usize * 4 + 2]),
            "phash case {n}"
        );
        assert_eq!(make_hash(term) as u64 + 1, reference[n as usize * 4 + 2]);
        assert_eq!(
            internal_hash(term),
            reference[n as usize * 4 + 3],
            "internal hash case {n}"
        );
        if !matches!(n % 8, 3 | 4) {
            assert_eq!(
                size_object(term) as u64,
                reference[n as usize * 4 + 1],
                "flat size case {n}"
            );
        }
    }
}

#[test]
fn copy_deep_list_and_tuple() {
    let mut source = VecHeap::new();
    let mut tail = Term::NIL;
    let list_len = if cfg!(miri) { 1_000 } else { 1_000_000 };
    for n in 0..list_len {
        tail = TermBuilder::new(&mut source)
            .cons(Term::small(n).unwrap(), tail)
            .unwrap();
    }
    let mut target = VecHeap::new();
    let copy = copy_term(tail, &mut target).unwrap();
    assert_eq!(target.used_words(), 2 * list_len as usize);
    assert!(exact_eq(tail, copy));
    let mut nested = Term::small(1).unwrap();
    let tuple_depth = if cfg!(miri) { 100 } else { 100_000 };
    for _ in 0..tuple_depth {
        nested = TermBuilder::new(&mut source).tuple(&[nested]).unwrap();
    }
    let mut target = VecHeap::new();
    let copy = copy_term(nested, &mut target).unwrap();
    assert_eq!(target.used_words(), 2 * tuple_depth);
    assert!(exact_eq(nested, copy));
}

#[test]
fn external_identities_and_copy() {
    use arinsal_term::{Identity, Node, global_atoms};
    let node = Node::new(global_atoms().intern("remote@host").unwrap(), 7);
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let pid = builder.external_pid(node.clone(), 42, 3).unwrap();
    let port = builder.external_port(node.clone(), 0x1_0000_0001).unwrap();
    let reference = builder.external_ref(node, &[1, 2, 3]).unwrap();
    assert_eq!(size_object(pid), 4);
    assert_eq!(size_object(port), 4);
    assert_eq!(size_object(reference), 5);
    assert!(matches!(
        pid.identity(),
        Some(Identity::Pid {
            index: 42,
            serial: 3,
            creation: 7,
            ..
        })
    ));
    assert!(matches!(
        port.identity(),
        Some(Identity::Port {
            id: 0x1_0000_0001,
            creation: 7,
            ..
        })
    ));
    assert!(
        matches!(reference.identity(), Some(Identity::Ref { ids, creation: 7, .. }) if ids == [1,2,3])
    );
    let mut copy_heap = VecHeap::new();
    let copied = copy_term(reference, &mut copy_heap).unwrap();
    assert!(exact_eq(reference, copied));
    assert!(matches!(to_owned(copied).unwrap(), OwnedTerm::Ref { ref ids, .. } if *ids == [1,2,3]));
}

#[test]
fn external_reference_id_counts_survive_copy_and_compare() {
    use arinsal_term::{Identity, Node, exact_eq, global_atoms};
    let node = Node::new(global_atoms().intern("refs@host").unwrap(), 7);
    for ids in [
        &[4711][..],
        &[4711, 0],
        &[4711, 0, 0],
        &[1, 2, 3, 4],
        &[1, 2, 3, 4, 5],
    ] {
        let mut source = VecHeap::new();
        let external = TermBuilder::new(&mut source)
            .external_ref(node.clone(), ids)
            .unwrap();
        assert!(
            matches!(external.identity(), Some(Identity::Ref { ids: actual, .. }) if actual == ids)
        );
        let mut target = VecHeap::new();
        let copied = copy_term(external, &mut target).unwrap();
        assert!(exact_eq(external, copied));
        let owned = to_owned(copied).unwrap();
        assert!(matches!(owned, OwnedTerm::Ref { ids: ref actual, .. } if actual == ids));
    }
}

#[test]
fn serialized_magic_reference_recovers_its_identity_after_owner_collection() {
    use arinsal_term::{Identity, MagicRef};
    let id = 0x1_0000_0000;
    let external = OwnedTerm::Ref {
        node: "nonode@nohost".into(),
        creation: 0,
        ids: vec![id as u32, (id >> 32) as u32, u32::MAX],
    };
    let mut heap = VecHeap::new();
    let reference = from_owned(&external, &mut heap).unwrap();
    assert!(reference.is_magic_ref());
    assert!(matches!(
        reference.identity(),
        Some(Identity::Ref { ids, .. }) if ids == [id as u32, (id >> 32) as u32, u32::MAX]
    ));
    assert!(matches!(
        to_owned(reference).unwrap(),
        OwnedTerm::Ref { ref ids, .. } if *ids == [id as u32, (id >> 32) as u32, u32::MAX]
    ));
    assert_eq!(MagicRef::live_by_id(id).unwrap().id(), id);
}

#[test]
fn fun_layout_copy_and_conversion() {
    use arinsal_term::{ExportEntry, FunEntry, FunRef, global_atoms};
    let module = global_atoms().intern("erlang").unwrap();
    let function = global_atoms().intern("length").unwrap();
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let exported = builder
        .export_fun(Arc::new(ExportEntry::new(module, function, 1)))
        .unwrap();
    assert_eq!(size_object(exported), 2);
    assert!(matches!(
        to_owned(exported).unwrap(),
        OwnedTerm::Export { arity: 1, .. }
    ));
    let entry = Arc::new(FunEntry {
        dispatch_target: Default::default(),
        pend_purge_address: Default::default(),
        module,
        arity: 1,
        index: 3,
        uniq: [7; 16],
        old_uniq: 9,
        old_index: 2,
        pid: Term::pid(4, 0).unwrap(),
        dispatch: Default::default(),
        dispatch_code: Default::default(),
        dispatch_epoch: Default::default(),
    });
    let local = builder
        .local_fun(entry, &[Term::small(42).unwrap()])
        .unwrap();
    assert_eq!(size_object(local), 3);
    // SAFETY: the owning heap is live and stable.
    let fun_view = unsafe { local.fun_ref().unwrap() };
    assert!(matches!(fun_view, FunRef::Local { .. }));
    let mut dst = VecHeap::new();
    let copied = copy_term(local, &mut dst).unwrap();
    assert!(exact_eq(local, copied));
    let owned = to_owned(copied).unwrap();
    let roundtrip = from_owned(&owned, &mut dst).unwrap();
    assert!(exact_eq(local, roundtrip));
    #[cfg(not(miri))]
    if let Some(reference) =
        erl_values("io:format(\"~w\",[erlang:phash2(fun erlang:length/1,4294967296)]),halt().")
    {
        assert_eq!(make_hash2(exported), reference[0]);
    }
}

#[test]
fn native_record_layout_order_hash_and_copy() {
    use arinsal_term::global_atoms;
    let module = global_atoms().intern("record_module").unwrap();
    let name = global_atoms().intern("record_name").unwrap();
    let alpha = global_atoms().intern("alpha").unwrap();
    let beta = global_atoms().intern("beta").unwrap();
    let zeta = global_atoms().intern("zeta").unwrap();
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let first = builder
        .native_record(
            module,
            name,
            true,
            &[
                (zeta, Term::small(9).unwrap()),
                (alpha, Term::small(2).unwrap()),
                (beta, Term::small(3).unwrap()),
            ],
        )
        .unwrap();
    let second = builder
        .native_record(
            module,
            name,
            true,
            &[
                (zeta, Term::small(10).unwrap()),
                (alpha, Term::small(2).unwrap()),
                (beta, Term::small(3).unwrap()),
            ],
        )
        .unwrap();
    assert!(first.is_record());
    // SAFETY: both record instances and definitions remain on the live heap.
    let view = unsafe { first.record_ref().unwrap() };
    assert_eq!(view.len(), 3);
    assert_eq!(view.key(0), Some(alpha));
    assert_eq!(view.key(1), Some(beta));
    assert_eq!(view.key(2), Some(zeta));
    assert_eq!(view.original_index(0), Some(1));
    assert_eq!(view.original_index(1), Some(2));
    assert_eq!(view.original_index(2), Some(0));
    assert_eq!(first.record_snapshot().unwrap().fields, [zeta, alpha, beta]);
    assert_eq!(cmp(first, second), Ordering::Less);
    assert_ne!(make_hash2(first), make_hash2(second));
    let mut dst = VecHeap::new();
    let copy = copy_term(first, &mut dst).unwrap();
    assert!(exact_eq(first, copy));
    assert_eq!(size_object(first), dst.used_words());
    let owned = to_owned(first).unwrap();
    assert_eq!(
        owned,
        OwnedTerm::Record {
            exported: true,
            module: "record_module".into(),
            name: "record_name".into(),
            fields: vec![
                ("zeta".into(), OwnedTerm::Int(9)),
                ("alpha".into(), OwnedTerm::Int(2)),
                ("beta".into(), OwnedTerm::Int(3)),
            ],
        }
    );
    let mut rebuilt_heap = VecHeap::new();
    let rebuilt = from_owned(&owned, &mut rebuilt_heap).unwrap();
    assert!(exact_eq(first, rebuilt));
}

#[test]
#[cfg(not(miri))]
fn differential_local_identities() {
    let expression = "erts_debug:set_internal_state(available_internal_state,true),L=[erlang:list_to_pid(\"<0.42.0>\"),erlang:list_to_port(\"#Port<0.123>\"),erlang:list_to_ref(\"#Ref<0.1.2.3>\")],lists:foreach(fun(T)->io:format(\"~w ~w ~w ~w~n\",[erlang:phash2(T,4294967296),erlang:phash(T,4294967296),erts_debug:get_internal_state({internal_hash,T}),erts_debug:flat_size(T)]) end,L),halt().";
    let Some(expected) = erl_values_u64(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(expected.len(), 12);
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let terms = [
        Term::pid(42, 0).unwrap(),
        Term::port(123).unwrap(),
        builder.local_ref([3, 2, 1]).unwrap(),
    ];
    for (i, term) in terms.iter().enumerate() {
        assert_eq!(make_hash2(*term) as u64, expected[i * 4]);
        assert_eq!(phash(*term, 1_u64 << 32), Some(expected[i * 4 + 1]));
        if i == 2 {
            assert_eq!(internal_hash(*term), expected[i * 4 + 2]);
        }
        assert_eq!(size_object(*term) as u64, expected[i * 4 + 3]);
    }
}

#[test]
#[cfg(not(miri))]
fn differential_atom_key_map_internal_hash() {
    let expression = "erts_debug:set_internal_state(available_internal_state,true),T=#{false=>1,error=>2},io:format(\"~w ~w ~w ~w~n\",[erlang:phash2(T,4294967296),erlang:phash(T,4294967296),erts_debug:get_internal_state({internal_hash,T}),erts_debug:flat_size(T)]),halt().";
    let Some(reference) = erl_values_u64(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 4);
    let abc = Term::atom(arinsal_term::atoms::ERROR);
    let false_atom = Term::atom(arinsal_term::atoms::FALSE);
    let mut heap = VecHeap::new();
    let map = TermBuilder::new(&mut heap)
        .flatmap_from_pairs(&[
            (abc, Term::small(2).unwrap()),
            (false_atom, Term::small(1).unwrap()),
        ])
        .unwrap();
    // SAFETY: map and key tuple remain on the live heap.
    let view = unsafe { map.flatmap_ref().unwrap() };
    assert_eq!(view.iter().next().unwrap().0, false_atom);
    assert_eq!(make_hash2(map) as u64, reference[0]);
    assert_eq!(phash(map, 1_u64 << 32), Some(reference[1]));
    assert_eq!(internal_hash(map), reference[2]);
    assert_eq!(size_object(map) as u64, reference[3]);
}

#[test]
fn unaligned_sub_binary_copy() {
    let mut source = VecHeap::new();
    let mut builder = TermBuilder::new(&mut source);
    let original = builder.binary(&[0xab, 0xcd, 0xef]).unwrap();
    let slice = builder.sub_binary(original, 3, 13).unwrap();
    assert_eq!(slice.header().unwrap() & 63, 0x20);
    let mut dst = VecHeap::new();
    let copy = copy_term(slice, &mut dst).unwrap();
    assert!(exact_eq(slice, copy));
    assert_eq!(size_object(slice), dst.used_words());
    assert_eq!(to_owned(slice).unwrap(), to_owned(copy).unwrap());
    #[cfg(not(miri))]
    if let Some(reference) = erl_values_u64(
        "erts_debug:set_internal_state(available_internal_state,true),<<_:3,S:13/bitstring,_/bitstring>> = <<16#AB,16#CD,16#EF>>,io:format(\"~w ~w ~w ~w~n\",[erlang:phash2(S,4294967296),erlang:phash(S,4294967296),erts_debug:get_internal_state({internal_hash,S}),bit_size(S)]),halt().",
    ) {
        assert_eq!(make_hash2(slice) as u64, reference[0]);
        assert_eq!(phash(slice, 1_u64 << 32), Some(reference[1]));
        assert_eq!(internal_hash(slice), reference[2]);
        assert_eq!(reference[3], 13);
    }
}

#[test]
fn unaligned_sub_binary_orders_against_literal_binary() {
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let aligned = builder.binary(&[1, 2, 3, 4]).unwrap();
    let mut backing = [0_u8; 65];
    for bit_index in 0..32 {
        let bit = ([1_u8, 2, 3, 4][bit_index / 8] >> (7 - bit_index % 8)) & 1;
        let target = bit_index + 3;
        backing[target / 8] |= bit << (7 - target % 8);
    }
    let backing = builder.binary(&backing).unwrap();
    let unaligned = builder.sub_binary(backing, 3, 32).unwrap();
    let literal = builder.binary(&[1, 2, 3, 5]).unwrap();

    assert_eq!(unaligned.header().unwrap() & 63, 0x24);
    assert_eq!(cmp(unaligned, aligned), Ordering::Equal);
    assert_eq!(cmp(unaligned, literal), Ordering::Less);
}

#[test]
#[cfg(not(miri))]
fn differential_binary_flat_size_for_matching_layouts() {
    let expression = "erts_debug:set_internal_state(available_internal_state,true),L=[iolist_to_binary([1,2,3]),list_to_binary(lists:duplicate(65,1))],lists:foreach(fun(B)->io:format(\"~w~n\",[erts_debug:flat_size(B)]) end,L),halt().";
    let Some(reference) = erl_values(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let small = builder.binary(&[1, 2, 3]).unwrap();
    let large = builder.binary(&[1; 65]).unwrap();
    assert_eq!(
        reference,
        vec![size_object(small) as u32, size_object(large) as u32]
    );
}

#[test]
fn offheap_sub_binary_retains_data_after_source_drops() {
    let mut source = VecHeap::new();
    let mut destination = VecHeap::new();
    let source_binary = TermBuilder::new(&mut source).binary(&[0xab; 128]).unwrap();
    let slice = TermBuilder::new(&mut destination)
        .sub_binary(source_binary, 3, 517)
        .unwrap();
    assert_eq!(slice.header().unwrap() & 63, 0x24);
    drop(source);
    let mut copy_heap = VecHeap::new();
    let copy = copy_term(slice, &mut copy_heap).unwrap();
    assert!(exact_eq(slice, copy));
    assert_eq!(size_object(slice), 8);
    assert_eq!(copy_heap.used_words(), 8);
}

#[test]
#[cfg(not(miri))]
fn differential_term_order_two_thousand_terms() {
    let expression = "F=fun(N)->case N rem 8 of 0->N-1000; 1->(1 bsl (60+N rem 30))+N; 2->(N-1000)/7; 3-><<(N band 255),((N bsr 3) band 255),((N bsr 8) band 255)>>; 4-><<(N band 31):5>>; 5->{N rem 97,N-1000,ok}; 6->[N band 255,(N bsr 8) band 255,N]; 7->#{(N rem 31)=>N,ok=> -N} end end,L=[{F(N),N}||N<-lists:seq(0,1999)],S=lists:sort(fun({A,I},{B,J})->A<B orelse (A==B andalso I=<J) end,L),lists:foreach(fun({_,N})->io:format(\"~w \",[N]) end,S),halt().";
    let Some(reference) = erl_values(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 2000);
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let ok = Term::atom(arinsal_term::atoms::OK);
    let mut terms = Vec::new();
    for n in 0..2000_i64 {
        let small = |value| Term::small(value).unwrap();
        let term = match n % 8 {
            0 => small(n - 1000),
            1 => builder
                .int_from_i128((1_i128 << (60 + n % 30)) + n as i128)
                .unwrap(),
            2 => builder.float((n - 1000) as f64 / 7.0).unwrap(),
            3 => builder
                .binary(&[n as u8, (n >> 3) as u8, (n >> 8) as u8])
                .unwrap(),
            4 => builder.bitstring(&[((n as u8) & 31) << 3], 5).unwrap(),
            5 => builder
                .tuple(&[small(n % 97), small(n - 1000), ok])
                .unwrap(),
            6 => builder
                .list_from_iter([small(n & 255), small((n >> 8) & 255), small(n)])
                .unwrap(),
            _ => builder
                .flatmap_from_pairs(&[(small(n % 31), small(n)), (ok, small(-n))])
                .unwrap(),
        };
        terms.push(term);
    }
    let mut indices: Vec<usize> = (0..terms.len()).collect();
    indices.sort_by(|&i, &j| cmp(terms[i], terms[j]).then(i.cmp(&j)));
    assert_eq!(
        indices.iter().map(|&i| i as u32).collect::<Vec<_>>(),
        reference
    );
}

#[test]
#[cfg(not(miri))]
fn differential_native_record_hashes() {
    let expression = "erts_debug:set_internal_state(available_internal_state,true),R=records:create(erlang,ok,[{error,9},{false,2}],#{is_exported=>true}),io:format(\"~w ~w ~w ~w~n\",[erlang:phash2(R,4294967296),erlang:phash(R,4294967296),erts_debug:get_internal_state({internal_hash,R}),erts_debug:flat_size(R)]),halt().";
    let Some(reference) = erl_values_u64(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 4);
    let mut heap = VecHeap::new();
    let record = TermBuilder::new(&mut heap)
        .native_record(
            arinsal_term::atoms::ERLANG,
            arinsal_term::atoms::OK,
            true,
            &[
                (arinsal_term::atoms::ERROR, Term::small(9).unwrap()),
                (arinsal_term::atoms::FALSE, Term::small(2).unwrap()),
            ],
        )
        .unwrap();
    assert_eq!(make_hash2(record) as u64, reference[0]);
    assert_eq!(phash(record, 1_u64 << 32), Some(reference[1]));
    assert_eq!(internal_hash(record), reference[2]);
    assert_eq!(size_object(record) as u64, reference[3]);
}

#[test]
#[cfg(not(miri))]
fn differential_local_fun_hashes() {
    let directory = std::env::temp_dir().join(format!("arinsal-term-fun-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = format!(
        "{}/tests/fixtures/arinsal_term_hash_fixture.erl",
        env!("CARGO_MANIFEST_DIR")
    );
    let Some(destination) = directory.to_str() else {
        return;
    };
    let Ok(compiled) = Command::new("erlc")
        .args(["-o", destination, &source])
        .output()
    else {
        eprintln!("skipping: erlc unavailable");
        return;
    };
    assert!(
        compiled.status.success(),
        "{}",
        String::from_utf8_lossy(&compiled.stderr)
    );
    let expression = "F=arinsal_term_hash_fixture:make(42),{new_index,I}=erlang:fun_info(F,new_index),{uniq,U}=erlang:fun_info(F,uniq),io:format(\"~w ~w ~w ~w ~w~n\",[I,U,erlang:phash2(F,4294967296),erlang:phash(F,4294967296),erts_debug:flat_size(F)]),halt().";
    let Ok(output) = Command::new("erl")
        .args(["-pa", destination, "-noshell", "-eval", expression])
        .output()
    else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let fields: Vec<u64> = String::from_utf8(output.stdout)
        .unwrap()
        .split_whitespace()
        .map(|value| value.parse().unwrap())
        .collect();
    assert_eq!(fields.len(), 5);
    let mut heap = VecHeap::new();
    let module = arinsal_term::global_atoms()
        .intern("arinsal_term_hash_fixture")
        .unwrap();
    let fun = TermBuilder::new(&mut heap)
        .local_fun(
            Arc::new(arinsal_term::FunEntry {
                dispatch_target: Default::default(),
                pend_purge_address: Default::default(),
                module,
                arity: 0,
                index: fields[0] as u32,
                uniq: [0; 16],
                old_index: 0,
                old_uniq: fields[1] as u32,
                pid: Term::pid(0, 0).unwrap(),
                dispatch: Default::default(),
                dispatch_code: Default::default(),
                dispatch_epoch: Default::default(),
            }),
            &[Term::small(42).unwrap()],
        )
        .unwrap();
    assert_eq!(make_hash2(fun) as u64, fields[2]);
    assert_eq!(phash(fun, 1_u64 << 32), Some(fields[3]));
    assert_eq!(size_object(fun) as u64, fields[4]);
}

#[test]
#[cfg(not(miri))]
fn differential_number_equality_truth_table() {
    let expression = "Pairs=[{0,0.0},{0.0,-0.0},{(1 bsl 53)+1,float((1 bsl 53)+1)},{1 bsl 53,float(1 bsl 53)},{-(1 bsl 60),-1152921504606846976.0},{1,1.5}],lists:foreach(fun({A,B})->io:format(\"~w ~w \",[case A==B of true->1;false->0 end,case A=:=B of true->1;false->0 end]) end,Pairs),halt().";
    let Some(reference) = erl_values(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 12);
    let mut heap = VecHeap::new();
    let mut b = TermBuilder::new(&mut heap);
    let zero = Term::small(0).unwrap();
    let one = Term::small(1).unwrap();
    let float_zero = b.float(0.0).unwrap();
    let neg_zero = b.float(-0.0).unwrap();
    let big_rounded = b.int_from_i128((1_i128 << 53) + 1).unwrap();
    let float_rounded = b.float(((1_i128 << 53) + 1) as f64).unwrap();
    let exact_big = b.int_from_i128(1_i128 << 53).unwrap();
    let exact_float = b.float((1_i128 << 53) as f64).unwrap();
    let negative_big = b.int_from_i128(-(1_i128 << 60)).unwrap();
    let negative_float = b.float(-(1_i128 << 60) as f64).unwrap();
    let one_point_five = b.float(1.5).unwrap();
    let pairs = [
        (zero, float_zero),
        (float_zero, neg_zero),
        (big_rounded, float_rounded),
        (exact_big, exact_float),
        (negative_big, negative_float),
        (one, one_point_five),
    ];
    for (i, (a, b)) in pairs.iter().enumerate() {
        assert_eq!(loose_eq(*a, *b) as u32, reference[i * 2], "loose pair {i}");
        assert_eq!(
            exact_eq(*a, *b) as u32,
            reference[i * 2 + 1],
            "exact pair {i}"
        );
    }
}

#[test]
#[cfg(not(miri))]
fn differential_integer_float_ordering_boundaries() {
    let expression = "Pairs=[{(1 bsl 53)+1,float((1 bsl 53)+1)},{-(1 bsl 53)-1,float(-(1 bsl 53)-1)},{(1 bsl 100)+1,float(1 bsl 100)},{-(1 bsl 100)-1,float(-(1 bsl 100))},{1,1.5},{2,1.5},{0,-0.0},{1,5.0e-324}],lists:foreach(fun({A,B})->io:format(\"~w \",[if A<B->0; A==B->1; true->2 end]) end,Pairs),halt().";
    let Some(reference) = erl_values(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let float = |builder: &mut TermBuilder<'_, VecHeap>, value: f64| builder.float(value).unwrap();
    let integer =
        |builder: &mut TermBuilder<'_, VecHeap>, value: i128| builder.int_from_i128(value).unwrap();
    let pairs = [
        (
            integer(&mut builder, (1_i128 << 53) + 1),
            float(&mut builder, ((1_i128 << 53) + 1) as f64),
        ),
        (
            integer(&mut builder, -(1_i128 << 53) - 1),
            float(&mut builder, (-(1_i128 << 53) - 1) as f64),
        ),
        (
            integer(&mut builder, (1_i128 << 100) + 1),
            float(&mut builder, (1_i128 << 100) as f64),
        ),
        (
            integer(&mut builder, -(1_i128 << 100) - 1),
            float(&mut builder, (-(1_i128 << 100)) as f64),
        ),
        (Term::small(1).unwrap(), float(&mut builder, 1.5)),
        (Term::small(2).unwrap(), float(&mut builder, 1.5)),
        (Term::small(0).unwrap(), float(&mut builder, -0.0)),
        (
            Term::small(1).unwrap(),
            float(&mut builder, f64::from_bits(1)),
        ),
    ];
    assert_eq!(reference.len(), pairs.len());
    for (index, (a, b)) in pairs.iter().enumerate() {
        let actual = match cmp(*a, *b) {
            Ordering::Less => 0,
            Ordering::Equal => 1,
            Ordering::Greater => 2,
        };
        assert_eq!(actual, reference[index], "numeric order case {index}");
    }
}

#[test]
#[cfg(not(miri))]
fn differential_hashes_ten_thousand_identities_and_funs() {
    let expression = "erts_debug:set_internal_state(available_internal_state,true),F=fun(N)->X=N rem 1000,case N rem 4 of 0->list_to_pid(\"<0.\"++integer_to_list(X)++\".0>\");1->list_to_port(\"#Port<0.\"++integer_to_list(X)++\">\");2->list_to_ref(\"#Ref<0.0.0.\"++integer_to_list(X)++\">\");3->fun erlang:length/1 end end,lists:foreach(fun(N)->T=F(N),io:format(\"~w ~w ~w ~w~n\",[erlang:phash2(T,4294967296),erlang:phash(T,4294967296),erts_debug:get_internal_state({internal_hash,T}),erts_debug:flat_size(T)]) end,lists:seq(0,9999)),halt().";
    let Some(reference) = erl_values_u64(expression) else {
        eprintln!("skipping: erl unavailable");
        return;
    };
    assert_eq!(reference.len(), 40_000);
    let mut heap = VecHeap::new();
    let mut builder = TermBuilder::new(&mut heap);
    let export = builder
        .export_fun(Arc::new(arinsal_term::ExportEntry::new(
            arinsal_term::atoms::ERLANG,
            arinsal_term::global_atoms().intern("length").unwrap(),
            1,
        )))
        .unwrap();
    for n in 0..10_000 {
        let id = n % 1000;
        let term = match n % 4 {
            0 => Term::pid(id, 0).unwrap(),
            1 => Term::port(id as u64).unwrap(),
            2 => builder.local_ref([id, 0, 0]).unwrap(),
            _ => export,
        };
        assert_eq!(
            make_hash2(term) as u64,
            reference[n as usize * 4],
            "phash2 case {n}"
        );
        assert_eq!(
            phash(term, 1_u64 << 32),
            Some(reference[n as usize * 4 + 1]),
            "phash case {n}"
        );
        if n % 4 == 2 {
            assert_eq!(
                internal_hash(term),
                reference[n as usize * 4 + 2],
                "internal case {n}"
            );
        }
        assert_eq!(
            size_object(term) as u64,
            reference[n as usize * 4 + 3],
            "size case {n}"
        );
    }
}

#[test]
fn magic_reference_uses_erts_ref_thing_header_and_marker() {
    // erl_term.h: ErtsMRefThing shares ERTS_REF_THING_HEADER with ErtsORefThing on 64-bit
    // little endian; the ordinary marker in word one tells them apart.
    use arinsal_term::{MagicRef, TermBuilder};
    let mut heap = VecHeap::new();
    let magic = TermBuilder::new(&mut heap)
        .magic_ref(MagicRef::new(()))
        .unwrap();
    let ordinary = TermBuilder::new(&mut heap).local_ref([1, 2, 3]).unwrap();
    assert_eq!(magic.header(), Some((2 << 6) | 0x10));
    assert_eq!(ordinary.header(), magic.header());
    assert!(magic.is_magic_ref());
    assert!(!ordinary.is_magic_ref());
    assert_eq!(magic.local_ref_numbers(), None);
    assert_eq!(ordinary.local_ref_numbers(), Some([1, 2, 3]));
    // SAFETY: `heap` retains both references and the magic owner for the borrow.
    assert!(unsafe { magic.magic_ref() }.is_some());
    // SAFETY: as above; an ordinary reference has no owner to borrow.
    assert!(unsafe { ordinary.magic_ref() }.is_none());
}
